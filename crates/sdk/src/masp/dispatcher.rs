use std::collections::BTreeMap;
use std::future::Future;
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
use typed_builder::TypedBuilder;

use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::masp::utils::{BlockRange, MaspClient};
use crate::masp::{
    to_viewing_key, DecryptedData, ScannedData,
    ShieldedContext, ShieldedUtils,
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
    UpdateCommitmentTree(CommitmentTree<Node>),
    UpdateNotesMap(BTreeMap<IndexedTx, usize>),
    UpdateWitness(HashMap<usize, IncrementalWitness<Node>>),
    FetchTxs(BlockRange),
    TrialDecrypt(
        (
            ScannedData,
            HashMap<Hash, (IndexedTx, ViewingKey, DecryptedData)>,
        ),
    ),
}

struct DispatcherTasks<Spawner> {
    spawner: Spawner,
    message_receiver: flume::Receiver<Result<Message, Error>>,
    message_sender: flume::Sender<Result<Message, Error>>,
    active_tasks: AsyncCounter,
    panic_flag: PanicFlag,
}

impl<Spawner> DispatcherTasks<Spawner> {
    async fn get_next_message(&mut self) -> Option<Result<Message, Error>> {
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
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
async fn new<S, M, U>(
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

    let (message_sender, message_receiver) = flume::bounded(config.channel_buffer_size);

    let tasks = DispatcherTasks {
        spawner,
        message_receiver,
        message_sender,
        active_tasks: AsyncCounter::new(),
        panic_flag: PanicFlag::default(),
    };

    Dispatcher {
        state,
        ctx,
        tasks,
        client,
        config,
        // TODO: add some kind of retry strategy,
        // when a fetch task fails
        //
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
    pub fn builder() -> DispatcherBuilder<M, U, S> {
        Default::defualt()
    }

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
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn_async(async move {
                client
                    .fetch_tx_notes_map(height)
                    .await
                    .map(Message::UpdateNotesMap)
            });
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn_async(async move {
                client
                    .fetch_commitment_tree(height)
                    .await
                    .map(Message::UpdateCommitmentTree)
            });
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn_async(async move {
                client
                    .fetch_witness_map(height)
                    .await
                    .map(Message::UpdateWitness)
            });
        }

        let batch_size = self.config.block_batch_size;
        for from in (initial_state.start_height.0 .. initial_state.last_query_height.0).step_by(batch_size) {
            let client = self.client.clone();
            let to = (from + batch_size as u64).min(initial_state.last_query_height.0);
            self.spawn_async(async move {
                client
                    .fetch_shielded_transfers(BlockHeight(from), BlockHeight(to))
                    .await
                    .map(Message::FetchTxs)
            });
        }
    }

    fn handle_incoming_message(&mut self, result: Result<Message, Error>) {
        if matches!(&self.state, DispatcherState::Errored(_)) {
            // TODO: we probably still want to cache things even
            // in the errored state!
            return;
        }

        let message = match result {
            Ok(m) => m,
            Err(err) => {
                // TODO: handle errors in fetch msgs
                self.state = DispatcherState::Errored(err);
                return;
            }
        };

        match message {
            Message::UpdateCommitmentTree(commitment_tree) => {
                // TODO: store the height of the last fetched tree,
                // to avoid refetching it
                self.ctx.tree = commitment_tree;
            }
            Message::UpdateNotesMap(notes_map) => {
                // TODO: store the height of the last fetched notes map,
                // to avoid refetching it
                if let DispatcherState::WaitingForNotesMap = &self.state {
                    self.state = DispatcherState::Normal;
                }
                self.ctx.tx_note_map = notes_map;
            }
            Message::UpdateWitness(witness_map) => {
                // TODO: store the height of the last fetched witness map,
                // to avoid refetching it
                self.ctx.witness_map = witness_map;
            }
            Message::FetchTxs(_tx_batch) => {
                todo!()
            }
            Message::TrialDecrypt(_decrypted_note_batch) => {
                todo!()
            }
        }
    }

    fn spawn_async<F>(&self, fut: F)
    where
        F: Future<Output = Result<Message, Error>> + 'static,
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
        F: FnOnce() -> Result<Message, Error> + Send + 'static,
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

#[derive(Default)]
pub struct DispatcherBuilder<M, U, S>
where
    U: ShieldedUtils,
{
    client: Option<M>,
    utils: Option<U>,
    spawner: Option<S>,
    channel_buffer_size: Option<usize>,
    block_batch_size: Option<usize>,
}

impl<M, U, S> DispatcherBuilder<M, U, S>
where
    M: MaspClient,
    U: ShieldedUtils
{
    const DEFAULT_BUF_SIZE: usize = 32;
    const DEFAULT_BATCH_SIZE: usize = 10;

    pub fn with_client(mut self, client: M) -> Self {
        self.client = Some(client);
        self
    }

    pub fn with_spawner(mut self, spawner: S) -> Self {
        self.spawner = Some(spawner);
        self
    }

    pub fn channel_buffer_size(mut self, size: usize) -> Self {
        self.channel_buffer_size = (size > 0).then_some(size);
        self
    }

    pub fn block_batch_size(mut self, size: usize) -> Self {
        self.block_batch_size = (size > 0).then_some(size);
        self
    }

    pub fn with_utils(mut self, utils: U) -> Self {
        self.utils = Some(utils);
        self
    }

    pub async fn build(self) -> Dispatcher<M, U, S> {
        new(
            self.spawner.expect("No spawner provided to the builder"),
            self.client.expect("No client provided to the builder"),
            self.utils.as_ref().expect("No utils provided to the builder"),
            Config {
                block_batch_size: self.block_batch_size.unwrap_or(Self::DEFAULT_BATCH_SIZE),
                channel_buffer_size: self.channel_buffer_size.unwrap_or(Self::DEFAULT_BUF_SIZE),
            }
        ).await
    }
}

