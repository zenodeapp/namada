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
use masp_primitives::transaction::Transaction;
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_core::collections::HashMap;
use namada_core::hints;
use namada_core::storage::BlockHeight;
use namada_tx::IndexedTx;

use super::utils::{IndexedNoteEntry, MaspClient};
use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::masp::shielded_sync::trial_decrypt;
use crate::masp::utils::{
    blocks_left_to_fetch, DecryptedData, Fetched, RetryStrategy, TrialDecrypted,
};
use crate::masp::{
    to_viewing_key, ShieldedContext, ShieldedUtils, TxNoteMap, WitnessMap,
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

    fn decrement_then_wake(&self) -> bool {
        // NB: if the prev value is 1, the new value
        // is eq to 0, which means we must wake the
        // waiting future
        self.count.fetch_sub(1, atomic::Ordering::Relaxed) == 1
    }

    fn value(&self) -> usize {
        self.count.load(atomic::Ordering::Relaxed)
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
        if self.inner.decrement_then_wake() {
            self.inner.waker.wake();
        }
    }
}

impl Future for AsyncCounter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if self.inner.value() == 0 {
            Poll::Ready(())
        } else {
            self.inner.waker.register(cx.waker());
            Poll::Pending
        }
    }
}

#[derive(Clone, Default)]
pub struct AtomicFlag {
    inner: Arc<AtomicBool>,
}

impl AtomicFlag {
    pub fn set(&self) {
        self.inner.store(true, atomic::Ordering::Relaxed)
    }

    pub fn get(&self) -> bool {
        self.inner.load(atomic::Ordering::Relaxed)
    }
}

#[derive(Clone, Default)]
struct PanicFlag {
    #[cfg(not(target_family = "wasm"))]
    inner: AtomicFlag,
}

impl PanicFlag {
    #[inline(always)]
    fn panicked(&self) -> bool {
        #[cfg(target_family = "wasm")]
        {
            false
        }

        #[cfg(not(target_family = "wasm"))]
        {
            self.inner.get()
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for PanicFlag {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.inner.set();
        }
    }
}

struct TaskError<C> {
    error: Error,
    context: C,
}

// TODO: avoid cloning viewing keys w/ arc-swap+lazy_static or
// rwlock+lazy_static
#[allow(clippy::large_enum_variant)]
enum Message {
    UpdateCommitmentTree(Result<CommitmentTree<Node>, TaskError<BlockHeight>>),
    UpdateNotesMap(Result<BTreeMap<IndexedTx, usize>, TaskError<BlockHeight>>),
    UpdateWitnessMap(
        Result<
            HashMap<usize, IncrementalWitness<Node>>,
            TaskError<BlockHeight>,
        >,
    ),
    FetchTxs(Result<Vec<IndexedNoteEntry>, TaskError<[BlockHeight; 2]>>),
    TrialDecrypt(IndexedTx, ViewingKey, Vec<DecryptedData>),
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

#[derive(Default)]
struct DispatcherCache {
    pub commitment_tree: Option<(BlockHeight, CommitmentTree<Node>)>,
    pub witness_map: Option<(BlockHeight, WitnessMap)>,
    pub tx_note_map: Option<(BlockHeight, TxNoteMap)>,
    pub fetched: Fetched,
    pub trial_decrypted: TrialDecrypted,
}

#[derive(Debug)]
enum DispatcherState {
    Normal,
    Interrupted,
    Errored(Error),
}

#[derive(Default, Debug)]
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
    /// We are syncing up to this height
    height_to_sync: BlockHeight,
    interrupt_flag: AtomicFlag,
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
    U: ShieldedUtils,
{
    let ctx = {
        let mut ctx = ShieldedContext {
            utils: utils.clone(),
            ..Default::default()
        };

        // TODO: defer loading of shielded context;
        // the only thing we need from it are potentially
        // viewking keys that had been stored on it
        if ctx.load_confirmed().await.is_err() {
            ctx = ShieldedContext {
                utils: utils.clone(),
                ..Default::default()
            };
        }

        ctx
    };

    let state = DispatcherState::Normal;

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
        height_to_sync: BlockHeight(0),
        state,
        ctx,
        tasks,
        client,
        config,
        cache,
        // TODO: add progress tracking mechanism to
        // `handle_incoming_message`
        interrupt_flag: Default::default(),
    }
}

impl<M, U, S> Dispatcher<M, U, S>
where
    M: MaspClient + Send + Sync + Unpin + 'static,
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
    ) -> Result<Option<ShieldedContext<U>>, Error> {
        let initial_state = self
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

        match self.state {
            DispatcherState::Errored(err) => {
                // TODO: save cache to file
                Err(err)
            }
            DispatcherState::Interrupted => {
                // TODO: save cache to file
                Ok(None)
            }
            DispatcherState::Normal => {
                // TODO: load shielded context at this stage

                self.apply_cache_to_shielded_context(&initial_state)?;
                self.ctx.save().await.map_err(|err| {
                    Error::Other(format!(
                        "Failed to save the shielded context: {err}"
                    ))
                })?;

                Ok(Some(self.ctx))
            }
        }
    }

    fn apply_cache_to_shielded_context(
        &mut self,
        InitialState {
            last_witnessed_tx, ..
        }: &InitialState,
    ) -> Result<(), Error> {
        if let Some((_, cmt)) = self.cache.commitment_tree.take() {
            self.ctx.tree = cmt;
        }
        if let Some((_, wm)) = self.cache.witness_map.take() {
            self.ctx.witness_map = wm;
        }
        if let Some((_, nm)) = self.cache.tx_note_map.take() {
            self.ctx.tx_note_map = nm;
        }

        for (indexed_tx, stx_batch) in self.cache.fetched.take() {
            if self.client.capabilities().needs_witness_map_update()
                && Some(&indexed_tx) > last_witnessed_tx.as_ref()
            {
                self.ctx.update_witness_map(indexed_tx, &stx_batch)?;
            }
            let mut note_pos = self.ctx.tx_note_map[&indexed_tx];
            let mut vk_heights = BTreeMap::new();
            std::mem::swap(&mut vk_heights, &mut self.ctx.vk_heights);
            for (vk, h) in vk_heights
                .iter_mut()
                .filter(|(_vk, h)| h.as_ref() < Some(&indexed_tx))
            {
                // TODO: test that we drain the entire cache of
                // decrypted notes (i.e.
                // `self.cache.trial_decrypted.is_empty()`)
                for (note, pa, memo) in self
                    .cache
                    .trial_decrypted
                    .take(&indexed_tx, vk)
                    .unwrap_or_default()
                {
                    self.ctx.save_decrypted_shielded_outputs(
                        vk, note_pos, note, pa, memo,
                    )?;
                    self.ctx.save_shielded_spends(&stx_batch);
                    note_pos += 1;
                }
                *h = Some(indexed_tx);
            }
            std::mem::swap(&mut vk_heights, &mut self.ctx.vk_heights);
        }

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

        self.height_to_sync = initial_state.last_query_height;
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
            tracing::info!("Interrupt received, shutting down shielded sync");
            self.state = DispatcherState::Interrupted;
            self.interrupt_flag.set();
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
            ..=initial_state.last_query_height.0)
            .step_by(batch_size)
        {
            let to = (from + batch_size as u64)
                .min(initial_state.last_query_height.0);
            self.spawn_fetch_txs(BlockHeight(from), BlockHeight(to));
        }

        for (itx, txs) in self.cache.fetched.iter() {
            self.spawn_trial_decryptions(*itx, txs);
        }
    }

    fn handle_incoming_message(&mut self, message: Message) {
        match message {
            Message::UpdateCommitmentTree(Ok(ct)) => {
                _ = self
                    .cache
                    .commitment_tree
                    .insert((self.height_to_sync, ct));
            }
            Message::UpdateCommitmentTree(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_commitment_tree(height);
                }
            }
            Message::UpdateNotesMap(Ok(nm)) => {
                _ = self.cache.tx_note_map.insert((self.height_to_sync, nm));
            }
            Message::UpdateNotesMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_tx_notes_map(height);
                }
            }
            Message::UpdateWitnessMap(Ok(wm)) => {
                _ = self.cache.witness_map.insert((self.height_to_sync, wm));
            }
            Message::UpdateWitnessMap(Err(TaskError {
                error,
                context: height,
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_update_witness_map(height);
                }
            }
            Message::FetchTxs(Ok(tx_batch)) => {
                for (itx, txs) in &tx_batch {
                    self.spawn_trial_decryptions(*itx, txs);
                }
                self.cache.fetched.extend(tx_batch);
            }
            Message::FetchTxs(Err(TaskError {
                error,
                context: [from, to],
            })) => {
                if self.can_launch_new_fetch_retry(error) {
                    self.spawn_fetch_txs(from, to);
                }
            }
            Message::TrialDecrypt(itx, vk, decrypted_data) => {
                self.cache.trial_decrypted.insert(itx, vk, decrypted_data);
            }
        }
    }

    /// Check if we can launch a new fetch task retry.
    fn can_launch_new_fetch_retry(&mut self, error: Error) -> bool {
        if matches!(
            self.state,
            DispatcherState::Errored(_) | DispatcherState::Interrupted
        ) {
            return false;
        }

        if self.config.retry_strategy.may_retry() {
            tracing::warn!(reason = %error, "Fetch failure, retrying...");
            true
        } else {
            // NB: store last encountered error
            self.state = DispatcherState::Errored(error);
            false
        }
    }

    fn spawn_update_witness_map(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.witness_map.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateWitnessMap(
                client.fetch_witness_map(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_update_commitment_tree(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.commitment_tree.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateCommitmentTree(
                client.fetch_commitment_tree(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_update_tx_notes_map(&mut self, height: BlockHeight) {
        if pre_built_in_cache(self.cache.tx_note_map.as_ref(), height) {
            return;
        }
        let client = self.client.clone();
        self.spawn_async(Box::pin(async move {
            Message::UpdateNotesMap(
                client.fetch_tx_notes_map(height).await.map_err(|error| {
                    TaskError {
                        error,
                        context: height,
                    }
                }),
            )
        }));
    }

    fn spawn_fetch_txs(&self, from: BlockHeight, to: BlockHeight) {
        for [from, to] in blocks_left_to_fetch(from, to, &self.cache.fetched) {
            let client = self.client.clone();
            self.spawn_async(Box::pin(async move {
                Message::FetchTxs(
                    client.fetch_shielded_transfers(from, to).await.map_err(
                        |error| TaskError {
                            error,
                            context: [from, to],
                        },
                    ),
                )
            }));
        }
    }

    fn spawn_trial_decryptions(&self, itx: IndexedTx, txs: &[Transaction]) {
        for tx in txs {
            for vk in self.ctx.vk_heights.keys() {
                let vk = *vk;

                if self.cache.trial_decrypted.get(&itx, &vk).is_none() {
                    let tx = tx.clone();
                    self.spawn_sync(move |interrupt| {
                        Message::TrialDecrypt(
                            itx,
                            vk,
                            trial_decrypt(tx, vk, interrupt),
                        )
                    })
                }
            }
        }
    }

    fn spawn_async<F>(&self, mut fut: F)
    where
        F: Future<Output = Message> + Unpin + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_async(async move {
            let _guard = guard;
            let wrapped_fut = std::future::poll_fn(move |cx| {
                if interrupt.get() {
                    Poll::Ready(None)
                } else {
                    Pin::new(&mut fut).poll(cx).map(Some)
                }
            });
            if let Some(msg) = wrapped_fut.await {
                sender.send_async(msg).await.unwrap()
            }
        });
    }

    fn spawn_sync<F>(&self, job: F)
    where
        F: FnOnce(AtomicFlag) -> Message + Send + 'static,
    {
        let sender = self.tasks.message_sender.clone();
        let guard = (
            self.tasks.active_tasks.clone(),
            self.tasks.panic_flag.clone(),
        );
        let interrupt = self.interrupt_flag.clone();
        self.tasks.spawner.spawn_sync(move || {
            let _guard = guard;
            sender.send(job(interrupt)).unwrap();
        });
    }
}

#[inline(always)]
fn pre_built_in_cache<T>(
    pre_built_data: Option<&(BlockHeight, T)>,
    desired_height: BlockHeight,
) -> bool {
    matches!(pre_built_data, Some((h, _)) if *h == desired_height)
}

#[cfg(test)]
mod dispatcher_tests {
    use std::collections::BTreeMap;
    use tempfile::tempdir;
    use namada_core::storage::BlockHeight;
    use namada_tx::IndexedTx;
    use crate::masp::fs::FsShieldedUtils;
    use crate::masp::ShieldedSyncConfig;
    use crate::masp::test_utils::{arbitrary_vk, TestingMaspClient};
    use crate::task_env::{LocalSetTaskEnvironment, TaskEnvironment};

    #[tokio::test]
    async fn test_applying_cache_drains_decrypted_data() {
        let client = TestingMaspClient::new(BlockHeight::first());
        let config = ShieldedSyncConfig::builder().client(client).build();
        let temp_dir = tempdir().unwrap();
        let utils = FsShieldedUtils {
            context_dir:  temp_dir.path().to_path_buf(),
        };
        let spawner = LocalSetTaskEnvironment::new(4)
            .expect("Test failed")
            .run(|s| async {
                let mut dispatcher = config.dispatcher(s, &utils).await;
                // fill up the dispatcher's cache
                for h in 0u64..10 {
                    let itx = IndexedTx {
                        height: h.into(),
                        index: Default::default(),
                    };
                    dispatcher.cache.fetched.insert((
                        itx,
                        vec![],
                    ));
                    dispatcher.ctx.tx_note_map.insert(itx, h as usize);
                    dispatcher.cache.trial_decrypted.insert(
                        itx,
                        arbitrary_vk(),
                        vec![],
                    )
                }

                dispatcher.apply_cache_to_shielded_context(
                    &Default::default()
                ).expect("Test failed");
                assert!(dispatcher.cache.fetched.is_empty());
                assert!(dispatcher.cache.trial_decrypted.is_empty());
                let expected = BTreeMap::from([(
                    arbitrary_vk(),
                    Some(IndexedTx{ height: 9.into(), index: Default::default() })
                )]);
                assert_eq!(expected, dispatcher.ctx.vk_heights);
            });
    }
}
#[cfg(test)]
mod test_dispatcher_tasks {
    use super::*;
    use crate::task_env::{LocalSetTaskEnvironment, TaskEnvironment};

    #[tokio::test]
    async fn test_async_counter_on_async_interrupt() {
        LocalSetTaskEnvironment::new(1)
            .unwrap()
            .run(|spawner| async move {
                let active_tasks = AsyncCounter::new();
                let interrupt = {
                    let int = AtomicFlag::default();

                    // preemptively set the task to an
                    // interrupted state
                    int.set();

                    int
                };

                // clone the active tasks handle,
                // to increment its internal ref count
                let guard = active_tasks.clone();

                let mut future = Box::pin(async move {
                    let _guard = guard;

                    // this future never yields, so the only
                    // wait to early exit is to be interrupted
                    // through the wrapped future
                    std::future::pending::<()>().await;
                });
                let interruptable_future = std::future::poll_fn(move |cx| {
                    if interrupt.get() {
                        // early exit here, by checking the interrupt state,
                        // which we immediately set above
                        Poll::Ready(())
                    } else {
                        Pin::new(&mut future).poll(cx)
                    }
                });

                spawner.spawn_async(interruptable_future);

                // sync with the spawned future by waiting
                // for the active tasks counter to reach zero
                active_tasks.await;
            })
            .await;
    }
}
