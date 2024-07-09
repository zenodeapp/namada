use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, ViewingKey};
use masp_primitives::zip32::ExtendedSpendingKey;
use namada_core::collections::HashMap;
use namada_core::hash::Hash;
use namada_core::storage::BlockHeight;
use namada_tx::IndexedTx;

use crate::control_flow::ShutdownSignal;
use crate::error::Error;
use crate::masp::utils::MaspClient;
use crate::masp::{
    to_viewing_key, DecryptedData, IndexedNoteEntry, ScannedData,
    ShieldedContext, ShieldedUtils,
};

#[derive(Debug)]
struct Weighted<W, T> {
    weight: W,
    value: T,
}

impl<W, T> Weighted<W, T> {
    const fn new(weight: W, value: T) -> Self {
        Self { weight, value }
    }
}

impl<W: PartialEq, T> PartialEq for Weighted<W, T> {
    fn eq(&self, other: &Self) -> bool {
        self.weight == other.weight
    }
}

impl<W: Eq, T> Eq for Weighted<W, T> {}

impl<W: PartialOrd, T> PartialOrd for Weighted<W, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.weight.partial_cmp(&other.weight)
    }
}

impl<W: Ord, T> Ord for Weighted<W, T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.weight.cmp(&other.weight)
    }
}

struct Task {
    receiver: tokio::sync::oneshot::Receiver<Result<Message, Error>>,
}

/// Tasks that the dispatcher can schedule
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TaskKind {
    FetchTxs = 0,
    TrialDecrypt = 1,
    UpdateCommitmentTree = 2,
    UpdateWitness = 3,
    UpdateNotesMap = 100,
}

pub enum Message {
    UpdateCommitmentTree(CommitmentTree<Node>),
    UpdateNotesMap(BTreeMap<IndexedTx, usize>),
    UpdateWitness(HashMap<usize, IncrementalWitness<Node>>),
    FetchTxs(Vec<IndexedNoteEntry>),
    TrialDecrypt(
        (
            ScannedData,
            HashMap<Hash, (IndexedTx, ViewingKey, DecryptedData)>,
        ),
    ),
}

struct DispatcherTasks {
    queue: BinaryHeap<Weighted<TaskKind, Task>>,
    max_msg_size: usize,
}

impl DispatcherTasks {
    #[inline]
    fn has_running_tasks(&self) -> bool {
        !self.queue.is_empty()
    }

    async fn retrieve_data_to_cache(
        self,
    ) -> (
        Vec<Vec<IndexedNoteEntry>>,
        Vec<(
            ScannedData,
            HashMap<Hash, (IndexedTx, ViewingKey, DecryptedData)>,
        )>,
    ) {
        let mut fetched_cache = vec![];
        let mut scanned_cache = vec![];
        for Weighted {
            value: Task { receiver },
            ..
        } in self.queue.into_vec()
        {
            match receiver.await {
                Ok(Ok(Message::FetchTxs(msg))) => fetched_cache.push(msg),
                Ok(Ok(Message::TrialDecrypt(msg))) => scanned_cache.push(msg),
                _ => {}
            }
        }
        (fetched_cache, scanned_cache)
    }
}

impl Future for DispatcherTasks {
    type Output = Vec<Result<Message, Error>>;

    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Self::Output> {
        if self.queue.is_empty() {
            return Poll::Ready(vec![]);
        }
        let tasks_to_check = self.queue.len().min(self.max_msg_size);
        let mut msgs = Vec::with_capacity(tasks_to_check);
        for _ in 0..tasks_to_check {
            let Weighted {
                weight: task_kind,
                value: mut task,
            } = self.queue.pop().unwrap();
            let pinned_rx = std::pin::pin!(&mut task.receiver);
            if let Poll::Ready(m) = pinned_rx.poll(cx) {
                msgs.push(m.unwrap_or_else(|_| {
                    panic!("Dispatched task halted unexpectedly")
                }));
            } else {
                self.queue.push(Weighted::new(task_kind, task))
            }
        }
        if msgs.is_empty() {
            Poll::Pending
        } else {
            Poll::Ready(msgs)
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

pub struct Dispatcher<M, U>
where
    U: ShieldedUtils,
{
    client: M,
    state: DispatcherState,
    tasks: DispatcherTasks,
    ctx: ShieldedContext<U>,
}

/// Create a new dispatcher in the initial state.
///
/// This function assumes that the provided shielded context has
/// already been loaded from storage.
pub async fn new<M: MaspClient, U: ShieldedUtils>(
    client: M,
    utils: &U,
) -> Dispatcher<M, U> {
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

    let tasks = DispatcherTasks {
        queue: BinaryHeap::new(),
        max_msg_size: 8,
    };

    Dispatcher {
        state,
        ctx,
        tasks,
        client,
        // TODO: add some kind of retry strategy,
        // when a fetch task fails
        //
        // TODO: add progress tracking mechanism to
        // `handle_incoming_message`
    }
}

impl<M, U> Dispatcher<M, U>
where
    M: MaspClient + Send + Sync + 'static,
    U: ShieldedUtils,
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

        while self.tasks.has_running_tasks() {
            let next_message_batch = {
                let pinned_tasks = std::pin::pin!(&mut self.tasks);
                pinned_tasks.await
            };

            self.check_if_interrupted(&mut shutdown_signal);

            for message in next_message_batch {
                self.handle_incoming_message(message);
            }
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

    fn check_if_interrupted(&mut self, shutdown_signal: &mut ShutdownSignal) {
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
        // TODO: spawn initial tasks
        // - fetch txs

        if self.client.capabilities().may_fetch_pre_built_notes_map() {
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn(TaskKind::UpdateNotesMap, async move {
                client
                    .fetch_tx_notes_map(height)
                    .await
                    .map(Message::UpdateNotesMap)
            });
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn(TaskKind::UpdateCommitmentTree, async move {
                client
                    .fetch_commitment_tree(height)
                    .await
                    .map(Message::UpdateCommitmentTree)
            });
        }

        if self.client.capabilities().may_fetch_pre_built_tree() {
            let client = self.client.clone();
            let height = initial_state.last_query_height;

            self.spawn(TaskKind::UpdateWitness, async move {
                client
                    .fetch_witness_map(height)
                    .await
                    .map(Message::UpdateWitness)
            });
        }
    }

    fn handle_incoming_message(&mut self, result: Result<Message, Error>) {
        if matches!(&self.state, DispatcherState::Errored(_)) {
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

    fn spawn<F>(&mut self, kind: TaskKind, fut: F)
    where
        F: Future<Output = Result<Message, Error>> + Send + 'static,
    {
        debug_assert!(
            !(matches!(&self.state, DispatcherState::WaitingForNotesMap)
                && kind == TaskKind::TrialDecrypt)
        );

        let (sender, receiver) = tokio::sync::oneshot::channel();

        self.tasks
            .queue
            .push(Weighted::new(kind, Task { receiver }));

        tokio::spawn(async move {
            let result = fut.await;
            sender.send(result).unwrap_or_else(|_| {
                panic!("Dispatcher has halted unexpectedly")
            });
        });
    }
}
