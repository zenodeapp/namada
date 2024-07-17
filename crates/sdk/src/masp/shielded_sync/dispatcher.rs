use std::collections::BTreeMap;
use std::future::Future;
use std::ops::ControlFlow;
use std::pin::Pin;
use std::sync::atomic::{self, AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::task::{Context, Poll};

use futures::future::{select, Either};
use futures::task::AtomicWaker;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::hints;
use namada_core::storage::BlockHeight;
use namada_tx::IndexedTx;

use super::utils::{BlockRange, MaspClient};
use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::masp::utils::{RetryStrategy, Unscanned};
use crate::masp::{
    to_viewing_key, DecryptedData, ScannedData, ShieldedContext, ShieldedUtils,
    TxNoteMap, WitnessMap,
};
use crate::task_env::TaskSpawner;

struct AsyncCounterInner {
    waker: AtomicWaker,
    count: AtomicUsize,
}

impl AsyncCounterInner {
    fn increment(&self) {
        self.count.fetch_add(1, atomic::Ordering::Relaxed);
    }
}

struct AsyncCounter {
    inner: Arc<AsyncCounterInner>,
}

impl AsyncCounter {
    fn new() -> Self {
        Self {
            inner: Arc::new(AsyncCounterInner {
                waker: AtomicWaker::new(),
                count: AtomicUsize::new(0),
            }),
        }
    }

    fn value(&self) -> usize {
        self.inner.count.load(atomic::Ordering::Relaxed)
    }
}

impl Clone for AsyncCounter {
    fn clone(&self) -> Self {
        let inner = Arc::clone(&self.inner);
        inner.increment();
        Self { inner }
    }
}

impl Drop for AsyncCounter {
    fn drop(&mut self) {
        if self.inner.count.fetch_sub(1, atomic::Ordering::Relaxed) == 1 {
            self.inner.waker.wake();
        }
    }
}

impl Future for AsyncCounter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.value() == 0 {
            Poll::Ready(())
        } else {
            self.inner.waker.register(cx.waker());
            Poll::Pending
        }
    }
}

#[derive(Clone, Default)]
struct PanicFlag {
    #[cfg(not(target_family = "wasm"))]
    inner: Arc<AtomicBool>,
}

impl PanicFlag {
    fn panicked(&self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            false
        }

        #[cfg(not(target_family = "wasm"))]
        {
            self.inner.load(atomic::Ordering::Relaxed)
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for PanicFlag {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.inner.store(true, atomic::Ordering::Relaxed);
        }
    }
}

pub enum Message {
    UpdateCommitmentTree(Result<CommitmentTree<Node>, BlockHeight>),
    UpdateNotesMap(Result<BTreeMap<IndexedTx, usize>, BlockHeight>),
    UpdateWitness(
        Result<HashMap<usize, IncrementalWitness<Node>>, BlockHeight>,
    ),
    FetchTxs(Result<BlockRange, [BlockHeight; 2]>),
    TrialDecrypt(
        Result<
            (
                ScannedData,
                HashMap<Hash, (IndexedTx, ViewingKey, DecryptedData)>,
            ),
            Error,
        >,
    ),
}

struct DispatcherTasks<Spawner> {
    spawner: Spawner,
    message_receiver: flume::Receiver<Message>,
    message_sender: flume::Sender<Message>,
    active_tasks: AsyncCounter,
    panic_flag: PanicFlag,
}

impl<Spawner> DispatcherTasks<Spawner> {
    async fn get_next_message(&mut self) -> Option<Message> {
        if let Either::Left((maybe_message, _)) =
            select(self.message_receiver.recv_async(), &mut self.active_tasks)
                .await
        {
            let Ok(message) = maybe_message else {
                unreachable!("There must be at least one sender alive");
            };
            Some(message)
        } else {
            None
        }
    }
}

pub enum Requested<T> {
    Received(T),
    Pending(BlockHeight),
}

#[derive(Default)]
struct DispatcherCache {
    pub commitment_tree: Requested<(BlockHeight, CommitmentTree<Node>)>,
    pub witness_map: Requested<(BlockHeight, WitnessMap)>,
    pub tx_note_map: Requested<(BlockHeight, TxNoteMap)>,
    pub unscanned: Unscanned,
}

#[derive(Debug)]
enum DispatcherState {
    Normal,
    WaitingForNotesMap,
    Interrupted,
    Errored(Error),
}

struct InitialState {
    last_witnessed_tx: Option<IndexedTx>,
    start_height: BlockHeight,
    last_query_height: BlockHeight,
}

pub struct Config {
    pub retry_strategy: RetryStrategy,
    pub block_batch_size: usize,
    pub channel_buffer_size: usize,
}

pub struct Dispatcher<M, U, S>
where
    U: ShieldedUtils,
{
    client: M,
    state: DispatcherState,
    tasks: DispatcherTasks<S>,
    ctx: ShieldedContext<U>,
    config: Config,
    cache: DispatcherCache,
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
pub async fn new<S, M, U>(
    spawner: S,
    client: M,
    utils: &U,
    config: Config,
) -> Dispatcher<M, U, S>
where
    M: MaspClient,
    U: ShieldedUtils,
{
    let ctx = {
        let mut ctx = ShieldedContext {
            utils: utils.clone(),
            ..Default::default()
        };

        if ctx.load_confirmed().await.is_err() {
            ctx = ShieldedContext {
                utils: utils.clone(),
                ..Default::default()
            };
        }

        ctx
    };

    let state = if client.capabilities().may_fetch_pre_built_notes_map() {
        // NB: if the client can fetch a pre-built notes map,
        // it won't build its own notes map, which means that
        // scanning will be delayed by completion of the notes
        // map fetch operation.
        DispatcherState::WaitingForNotesMap
    } else {
        DispatcherState::Normal
    };

    let (message_sender, message_receiver) =
        flume::bounded(config.channel_buffer_size);

    let tasks = DispatcherTasks {
        spawner,
        message_receiver,
        message_sender,
        active_tasks: AsyncCounter::new(),
        panic_flag: PanicFlag::default(),
    };

    // TODO: load cache from file
    let cache = DispatcherCache::default();

    Dispatcher {
        state,
        ctx,
        tasks,
        client,
        config,
        cache,
        // TODO: add progress tracking mechanism to
        // `handle_incoming_message`
    }
}

impl<M, U, S> Dispatcher<M, U, S>
where
    M: MaspClient + Send + Sync + 'static,
    U: ShieldedUtils,
    S: TaskSpawner,
{
    pub async fn run(
        mut self,
        mut shutdown_signal: ShutdownSignal,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<(), Error> {
        let _initial_state = self
            .perform_initial_setup(
                start_query_height,
                last_query_height,
                sks,
                fvks,
            )
            .await?;

        while let Some(message) = self.tasks.get_next_message().await {
            self.check_exit_conditions(&mut shutdown_signal);
            self.handle_incoming_message(message);
        }

        if let DispatcherState::Errored(err) = self.state {
            return Err(err);
        }

        self.ctx.save().await.map_err(|err| {
            Error::Other(format!("Failed to save the shielded context: {err}"))
        })?;

        Ok(())
    }

    async fn perform_initial_setup(
        &mut self,
        start_query_height: Option<BlockHeight>,
        last_query_height: Option<BlockHeight>,
        sks: &[ExtendedSpendingKey],
        fvks: &[ViewingKey],
    ) -> Result<InitialState, Error> {
        if start_query_height > last_query_height {
            return Err(Error::Other(format!(
                "The start height {start_query_height:?} cannot be higher \
                 than the ending height {last_query_height:?} in the shielded \
                 sync"
            )));
        }

        for esk in sks {
            let vk = to_viewing_key(esk).vk;
            self.ctx.vk_heights.entry(vk).or_default();
        }
        for vk in fvks {
            self.ctx.vk_heights.entry(*vk).or_default();
        }

        // the latest block height which has been added to the witness Merkle
        // tree
        let last_witnessed_tx = self.ctx.tx_note_map.keys().max().cloned();

        // Query for the last produced block height
        let Some(last_block_height) = self.client.last_block_height().await?
        else {
            return Err(Error::Other(
                "No block has been committed yet".to_string(),
            ));
        };

        let last_query_height = last_query_height
            .unwrap_or(last_block_height)
            // NB: limit fetching until the last committed height
            .min(last_block_height);

        let start_height = start_query_height
            .map_or_else(|| self.ctx.min_height_to_sync_from(), Ok)?
            // NB: the start height cannot be greater than
            // `last_query_height`
            .min(last_query_height);

        let initial_state = InitialState {
            last_witnessed_tx,
            last_query_height,
            start_height,
        };

        self.spawn_initial_set_of_tasks(&initial_state);

        Ok(initial_state)
    }

    fn check_exit_conditions(&mut self, shutdown_signal: &mut ShutdownSignal) {
        if hints::unlikely(self.tasks.panic_flag.panicked()) {
            self.state = DispatcherState::Errored(Error::Other(
                "A worker thread panicked during the shielded sync".into(),
            ));
        }
        if matches!(
            &self.state,
            DispatcherState::Interrupted | DispatcherState::Errored(_)
        ) {
            return;
        }
        if shutdown_signal.received() {
            self.state = DispatcherState::Interrupted;
        }
    }

    fn spawn_initial_set_of_tasks(&mut self, initial_state: &InitialState) {
        if self.client.capabilities().may_fetch_pre_built_notes_map() {
            self.spawn_update_tx_notes_map(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            self.spawn_update_commitment_tree(initial_state.last_query_height);
        }

        if self.client.capabilities().may_fetch_pre_built_witness_map() {
            self.spawn_update_witness_map(initial_state.last_query_height);
        }

        let batch_size = self.config.block_batch_size;
        for from in (initial_state.start_height.0
            ..initial_state.last_query_height.0)
            .step_by(batch_size)
        {
            let client = self.client.clone();
            let to = (from + batch_size as u64)
                .min(initial_state.last_query_height.0);
            self.spawn_async(async move {
                client
                    .fetch_shielded_transfers(
                        BlockHeight(from),
                        BlockHeight(to),
                    )
                    .await
                    .map(Message::FetchTxs)
            });
        }
    }

    fn handle_incoming_message(&mut self, message: Message) -> ControlFlow<()> {
        match message {
            Message::UpdateCommitmentTree(commitment_tree) => {
                match commitment_tree {
                    Ok(ct) => self.cache.commitment_tree = Some((height, ct)),
                    Err(height) => {
                        self.can_launch_new_fetch_retry()?;
                        self.spawn_update_commitment_tree(height);
                    }
                }
            }
            Message::UpdateNotesMap(notes_map) => match notes_map {
                Ok(nm) => {
                    if let DispatcherState::WaitingForNotesMap = &self.state {
                        self.state = DispatcherState::Normal;
                    }
                    self.ctx.tx_note_map = nm;
                }
                Err(height) => {
                    self.can_launch_new_fetch_retry()?;
                    self.spawn_update_tx_notes_map(height);
                }
            },
            Message::UpdateWitness(witness_map) => match witness_map {
                Ok(wm) => self.ctx.witness_map = wm,
                Err(height) => {
                    self.can_launch_new_fetch_retry()?;
                    self.spawn_update_witness_map(height);
                }
            },
            Message::FetchTxs(tx_batch) => match tx_batch {
                Ok(tx_batch) => {}
                Err([from, to]) => {
                    self.can_launch_new_fetch_retry()?;
                    self.spawn_fetch_tx(from, to);
                }
            },
            Message::TrialDecrypt(_decrypted_note_batch) => {
                todo!()
            }
        }
        ControlFlow::Continue(())
    }

    /// Check if we can launch a new fetch task retry.
    fn can_launch_new_fetch_retry(&mut self) -> ControlFlow<()> {
        if matches!(
            self.state,
            DispatcherState::Errored(_) | DispatcherState::Interrupted
        ) {
            ControlFlow::Break(())
        } else {
            self.config.retry_strategy.retry()
        }
    }

    fn spawn_update_witness_map(&mut self, height: BlockHeight) {
        match self.cache.witness_map.take() {
            Some((h, wm)) if h == height => {
                self.spawn_async(async move { Message::UpdateWitness(Ok(wm)) })
            }
            _ => {
                let client = self.client.clone();
                self.spawn_async(async move {
                    client
                        .fetch_witness_map(height)
                        .await
                        .map(Message::UpdateWitness)
                        .map_err(|_| height)
                })
            }
        }
    }

    fn spawn_update_commitment_tree(&mut self, height: BlockHeight) {
        match self.cache.commitment_tree.take() {
            Some((h, ct)) if h == height => self.spawn_async(async move {
                Message::UpdateCommitmentTree(Ok(ct))
            }),
            _ => {
                let client = self.client.clone();
                self.spawn_async(async move {
                    client
                        .fetch_commitment_tree(height)
                        .await
                        .map(Message::UpdateCommitmentTree)
                        .map_err(|_| height)
                });
            }
        }
    }

    fn spawn_update_tx_notes_map(&mut self, height: BlockHeight) {
        match self.cache.tx_note_map.take() {
            Some((h, nm)) if h == height => {
                self.spawn_async(async move { Message::UpdateNotesMap(Ok(nm)) })
            }
            _ => {
                let client = self.client.clone();
                self.spawn_async(async move {
                    client
                        .fetch_tx_notes_map(height)
                        .await
                        .map(Message::UpdateNotesMap)
                        .map_err(|_| height)
                });
            }
        }
    }

    fn spawn_fetch_tx(&self, from: BlockHeight, to: BlockHeight) {
        let client = self.client.clone();
        self.spawn_async(async move {
            client
                .fetch_shielded_transfers(from, to)
                .await
                .map(Message::FetchTxs)
                .map_err(|_| [from, to])
        })
    }

    fn spawn_async<F>(&self, fut: F)
    where
        F: Future<Output = Message> + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );

        self.tasks.spawner.spawn_async(async move {
            let _guard = guard;
            sender.send_async(fut.await).await.unwrap();
        });
    }

    fn spawn_sync<F>(&self, job: F)
    where
        F: FnOnce() -> Message + Send + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );

        self.tasks.spawner.spawn_sync(move || {
            let _guard = guard;
            sender.send(job()).unwrap();
        });
    }
}
