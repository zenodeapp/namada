//! Helper functions and types

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use borsh::{BorshDeserialize, BorshSerialize};
use masp_primitives::memo::MemoBytes;
use masp_primitives::merkle_tree::{CommitmentTree, IncrementalWitness};
use masp_primitives::sapling::{Node, Note, PaymentAddress, ViewingKey};
use masp_primitives::transaction::Transaction;
use namada_core::collections::HashMap;
use namada_core::storage::{BlockHeight, TxIndex};
use namada_tx::{IndexedTx, IndexedTxRange, Tx};

use crate::error::{Error, QueryError};
use crate::io::Io;
use crate::masp::{
    extract_masp_tx, extract_masp_tx_from_ibc_message,
    get_indexed_masp_events_at_height,
};
use crate::queries::Client;

/// Type alias for convenience and profit
pub type IndexedNoteData = BTreeMap<IndexedTx, Vec<Transaction>>;

/// Type alias for the entries of [`IndexedNoteData`] iterators
pub type IndexedNoteEntry = (IndexedTx, Vec<Transaction>);

/// Borrowed version of an [`IndexedNoteEntry`]
pub type IndexedNoteEntryRefs<'a> = (&'a IndexedTx, &'a Vec<Transaction>);

/// Type alias for a successful note decryption.
pub type DecryptedData = (Note, PaymentAddress, MemoBytes);

/// Cache of decrypted notes.
#[derive(Default)]
pub struct TrialDecrypted {
    inner: HashMap<IndexedTx, HashMap<ViewingKey, Vec<DecryptedData>>>,
}

impl TrialDecrypted {
    /// Get cached notes decrypted with `vk`, indexed at `itx`.
    pub fn get(
        &self,
        itx: &IndexedTx,
        vk: &ViewingKey,
    ) -> Option<&Vec<DecryptedData>> {
        self.inner.get(itx).and_then(|h| h.get(vk))
    }

    /// Take cached notes decrypted with `vk`, indexed at `itx`.
    pub fn take(
        &mut self,
        itx: &IndexedTx,
        vk: &ViewingKey,
    ) -> Option<Vec<DecryptedData>> {
        let (notes, no_more_notes) = {
            let viewing_keys_to_notes = self.inner.get_mut(itx)?;
            let notes = viewing_keys_to_notes.swap_remove(vk)?;
            (notes, viewing_keys_to_notes.is_empty())
        };
        if no_more_notes {
            self.inner.swap_remove(itx);
        }
        Some(notes)
    }

    /// Cache `notes` decrypted with `vk`, indexed at `itx`.
    pub fn insert(
        &mut self,
        itx: IndexedTx,
        vk: ViewingKey,
        notes: Vec<DecryptedData>,
    ) {
        self.inner.entry(itx).or_default().insert(vk, notes);
    }
}

/// A cache of fetched indexed transactions.
///
/// An invariant that shielded-sync maintains is that
/// this cache either contains all transactions from
/// a given height, or none.
#[derive(Debug, Default, Clone, BorshSerialize, BorshDeserialize)]
pub struct Fetched {
    txs: IndexedNoteData,
}

impl Fetched {
    /// Append elements to the cache from an iterator.
    pub fn extend<I>(&mut self, items: I)
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        self.txs.extend(items);
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks.
    pub fn iter(
        &self,
    ) -> impl IntoIterator<Item = IndexedNoteEntryRefs<'_>> + '_ {
        &self.txs
    }

    /// Iterates over the fetched transactions in the order
    /// they appear in blocks, whilst taking ownership of
    /// the returned data.
    pub fn take(&mut self) -> impl IntoIterator<Item = IndexedNoteEntry> {
        std::mem::take(&mut self.txs)
    }

    /// Add a single entry to the cache.
    pub fn insert(&mut self, (k, v): IndexedNoteEntry) {
        self.txs.insert(k, v);
    }

    /// Check if this cache has already been populated for a given
    /// block height.
    pub fn contains_height(&self, height: BlockHeight) -> bool {
        self.txs
            .range(IndexedTxRange::with_height(height))
            .next()
            .is_some()
    }

    /// Check if this cache has already been populated for a given
    /// block height.
    pub fn txs_in_range(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> impl Iterator<Item = IndexedNoteEntryRefs<'_>> + '_ {
        self.txs.range(IndexedTxRange::between_heights(from, to))
    }

    /// We remove all indices from blocks that have been entirely scanned.
    /// If a block is only partially scanned, we leave all the events in the
    /// cache.
    pub fn scanned(&mut self, ix: &IndexedTx) {
        self.txs.retain(|i, _| i.height >= ix.height);
    }

    /// Gets the latest block height present in the cache
    pub fn latest_height(&self) -> BlockHeight {
        self.txs
            .keys()
            .max_by_key(|ix| ix.height)
            .map(|ix| ix.height)
            .unwrap_or_default()
    }

    /// Gets the first block height present in the cache
    pub fn first_height(&self) -> BlockHeight {
        self.txs
            .keys()
            .min_by_key(|ix| ix.height)
            .map(|ix| ix.height)
            .unwrap_or_default()
    }

    /// Remove the first entry from the cache and return it.
    pub fn pop_first(&mut self) -> Option<IndexedNoteEntry> {
        self.txs.pop_first()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.txs.is_empty()
    }
}

impl IntoIterator for Fetched {
    type IntoIter = <IndexedNoteData as IntoIterator>::IntoIter;
    type Item = IndexedNoteEntry;

    fn into_iter(mut self) -> Self::IntoIter {
        let txs = std::mem::take(&mut self.txs);
        txs.into_iter()
    }
}

/// When retrying to fetch all notes in a
/// loop, this dictates the strategy for
/// how many attempts should be made.
pub enum RetryStrategy {
    /// Always retry
    Forever,
    /// Limit number of retries to a fixed number
    Times(u64),
}

impl RetryStrategy {
    /// Check if retries are exhausted.
    pub fn may_retry(&mut self) -> bool {
        match self {
            RetryStrategy::Forever => true,
            RetryStrategy::Times(left) => {
                if *left == 0 {
                    false
                } else {
                    *left -= 1;
                    true
                }
            }
        }
    }
}

/// Enumerates the capabilities of a [`MaspClient`] implementation.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum MaspClientCapabilities {
    /// The masp client implementation is only capable of fetching shielded
    /// transfers.
    OnlyTransfers,
    /// The masp client implementation is capable of not only fetching shielded
    /// transfers, but also of fetching commitment trees, witness maps, and
    /// note maps.
    AllData,
}

impl MaspClientCapabilities {
    /// Check if the lack of one or more capabilities in the
    /// masp client implementation warrants a manual update
    /// of the witnesses map.
    pub const fn needs_witness_map_update(&self) -> bool {
        matches!(self, Self::OnlyTransfers)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// commitment tree.
    pub const fn may_fetch_pre_built_tree(&self) -> bool {
        matches!(self, Self::AllData)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// notes map.
    pub const fn may_fetch_pre_built_notes_map(&self) -> bool {
        matches!(self, Self::AllData)
    }

    /// Check if the masp client is able to fetch a pre-built
    /// witness map.
    pub const fn may_fetch_pre_built_witness_map(&self) -> bool {
        matches!(self, Self::AllData)
    }
}

/// This abstracts away the implementation details
/// of how shielded-sync fetches the necessary data
/// from a remote server.
// TODO: redesign this api with progress bars in mind
pub trait MaspClient: Clone {
    /// Return the last block height we can retrieve data from.
    #[allow(async_fn_in_trait)]
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error>;

    /// Fetch shielded transfers from blocks heights in the range `[from, to]`,
    /// keeping track of progress through `progress`. The fetched transfers
    /// are sent over to a separate worker through `tx_sender`.
    #[allow(async_fn_in_trait)]
    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error>;

    /// Return the capabilities of this client.
    fn capabilities(&self) -> MaspClientCapabilities;

    /// Fetch the commitment tree of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_commitment_tree(
        &self,
        height: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error>;

    /// Fetch the tx notes map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_tx_notes_map(
        &self,
        height: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error>;

    /// Fetch the witness map of height `height`.
    #[allow(async_fn_in_trait)]
    async fn fetch_witness_map(
        &self,
        height: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error>;
}

/// An inefficient MASP client which simply uses a
/// client to the blockchain to query it directly.
#[cfg(not(target_family = "wasm"))]
pub struct LedgerMaspClient<C> {
    client: Arc<C>,
}

impl<C> Clone for LedgerMaspClient<C> {
    fn clone(&self) -> Self {
        Self {
            client: Arc::clone(&self.client),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<C> LedgerMaspClient<C> {
    /// Create a new [`MaspClient`] given an rpc client.
    #[inline(always)]
    pub fn new(client: C) -> Self {
        Self {
            client: Arc::new(client),
        }
    }
}

#[cfg(not(target_family = "wasm"))]
impl<C: Client + Send + Sync> MaspClient for LedgerMaspClient<C> {
    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        let maybe_block = crate::rpc::query_block(&*self.client).await?;
        Ok(maybe_block.map(|b| b.height))
    }

    async fn fetch_shielded_transfers(
        &self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        // Fetch all the transactions we do not have yet
        let mut txs = vec![];

        for height in from.0..=to.0 {
            // TODO: Fix
            // if tx_sender.contains_height(height) {
            //     continue;
            // }

            let txs_results = match get_indexed_masp_events_at_height(
                &*self.client,
                height.into(),
                None,
            )
            .await?
            {
                Some(events) => events,
                None => {
                    continue;
                }
            };

            // Query the actual block to get the txs bytes. If we only need one
            // tx it might be slightly better to query the /tx endpoint to
            // reduce the amount of data sent over the network, but this is a
            // minimal improvement and it's even hard to tell how many times
            // we'd need a single masp tx to make this worth it
            let block = self
                .client
                .block(height as u32)
                .await
                .map_err(|e| Error::from(QueryError::General(e.to_string())))?
                .block
                .data;
            for (idx, masp_sections_refs) in txs_results {
                let tx = Tx::try_from(block[idx.0 as usize].as_ref())
                    .map_err(|e| Error::Other(e.to_string()))?;
                let extracted_masp_txs =
                    if let Some(masp_sections_refs) = masp_sections_refs {
                        extract_masp_tx(&tx, &masp_sections_refs).await?
                    } else {
                        extract_masp_tx_from_ibc_message(&tx)?
                    };
                txs.push((
                    IndexedTx {
                        height: height.into(),
                        index: idx,
                    },
                    extracted_masp_txs,
                ));
            }
        }

        Ok(txs)
    }

    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::OnlyTransfers
    }

    async fn fetch_commitment_tree(
        &self,
        _: BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        Err(Error::Other(
            "Commitment tree fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_tx_notes_map(
        &self,
        _: BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        Err(Error::Other(
            "Transaction notes map fetching is not implemented by this client"
                .to_string(),
        ))
    }

    async fn fetch_witness_map(
        &self,
        _: BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        Err(Error::Other(
            "Witness map fetching is not implemented by this client"
                .to_string(),
        ))
    }
}

/// MASP client implementation that queries data from the
/// [`namada-masp-indexer`].
///
/// [`namada-masp-indexer`]: <https://github.com/anoma/namada-masp-indexer>
#[cfg(not(target_family = "wasm"))]
#[derive(Clone, Debug)]
pub struct IndexerMaspClient {
    indexer_api: Arc<reqwest::Url>,
    client: reqwest::Client,
}

#[cfg(not(target_family = "wasm"))]
trait RequestBuilderExt {
    fn keep_alive(self) -> reqwest::RequestBuilder;
}

#[cfg(not(target_family = "wasm"))]
impl RequestBuilderExt for reqwest::RequestBuilder {
    #[inline(always)]
    fn keep_alive(self) -> reqwest::RequestBuilder {
        self.header("Connection", "Keep-Alive")
    }
}

#[cfg(not(target_family = "wasm"))]
impl IndexerMaspClient {
    /// Create a new [`IndexerMaspClient`].
    #[inline]
    pub fn new(client: reqwest::Client, indexer_api: reqwest::Url) -> Self {
        let indexer_api = Arc::new(indexer_api);
        Self {
            client,
            indexer_api,
        }
    }

    fn endpoint(&self, which: &str) -> String {
        format!("{}{which}", self.indexer_api)
    }

    async fn get_server_error(
        response: reqwest::Response,
    ) -> Result<String, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            message: String,
        }

        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize server's error JSON response: {err}"
            ))
        })?;

        Ok(payload.message)
    }
}

#[cfg(not(target_family = "wasm"))]
impl MaspClient for IndexerMaspClient {
    #[inline(always)]
    fn capabilities(&self) -> MaspClientCapabilities {
        MaspClientCapabilities::AllData
    }

    async fn last_block_height(&self) -> Result<Option<BlockHeight>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            block_height: u64,
        }

        let response = self
            .client
            .get(self.endpoint("/height"))
            .keep_alive()
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch latest block height: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch last block height: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize latest block height JSON response: \
                 {err}"
            ))
        })?;

        Ok(if payload.block_height != 0 {
            Some(BlockHeight(payload.block_height))
        } else {
            None
        })
    }

    async fn fetch_shielded_transfers(
        &self,
        BlockHeight(mut from): BlockHeight,
        BlockHeight(to): BlockHeight,
    ) -> Result<Vec<IndexedNoteEntry>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct TransactionSlot {
            // masp_tx_index: u64,
            bytes: Vec<u8>,
        }

        #[derive(Deserialize)]
        struct Transaction {
            batch: Vec<TransactionSlot>,
            block_index: u32,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct TxResponse {
            txs: Vec<Transaction>,
        }

        if from > to {
            return Err(Error::Other(format!(
                "Invalid block range {from}-{to}: Beginning height {from} is \
                 greater than ending height {to}"
            )));
        }

        const MAX_RANGE_THRES: u64 = 30;
        let mut txs = vec![];

        loop {
            let from_height = from;
            let off = (to - from).min(MAX_RANGE_THRES);
            let to_height = from + off;
            from += off;

            let payload: TxResponse = {
                let response = self
                    .client
                    .get(self.endpoint("/tx"))
                    .keep_alive()
                    .query(&[("height", from_height), ("height_offset", off)])
                    .send()
                    .await
                    .map_err(|err| {
                        Error::Other(format!(
                            "Failed to fetch transactions in the height range \
                             {from_height}-{to_height}: {err}"
                        ))
                    })?;
                if !response.status().is_success() {
                    let err = Self::get_server_error(response).await?;
                    return Err(Error::Other(format!(
                        "Failed to fetch transactions in the range \
                         {from_height}-{to_height}: {err}"
                    )));
                }
                response.json().await.map_err(|err| {
                    Error::Other(format!(
                        "Could not deserialize the transactions JSON response \
                         in the height range {from_height}-{to_height}: {err}"
                    ))
                })?
            };

            for Transaction {
                batch,
                block_index,
                block_height,
            } in payload.txs
            {
                let mut extracted_masp_txs = Vec::with_capacity(batch.len());

                for TransactionSlot { bytes } in batch {
                    type MaspTx = masp_primitives::transaction::Transaction;

                    extracted_masp_txs.push(
                        MaspTx::try_from_slice(&bytes).map_err(|err| {
                            Error::Other(format!(
                                "Could not deserialize the masp txs borsh \
                                 data at height {block_height} and index \
                                 {block_index}: {err}"
                            ))
                        })?,
                    );
                }

                txs.push((
                    IndexedTx {
                        height: BlockHeight(block_height),
                        index: TxIndex(block_index),
                    },
                    extracted_masp_txs,
                ));
            }

            if from >= to {
                break;
            }
        }

        Ok(txs)
    }

    async fn fetch_commitment_tree(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<CommitmentTree<Node>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Response {
            commitment_tree: Vec<u8>,
        }

        let response = self
            .client
            .get(self.endpoint("/commitment-tree"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch commitment tree at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch commitment tree at height {height}: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the commitment tree JSON response at \
                 height {height}: {err}"
            ))
        })?;

        BorshDeserialize::try_from_slice(&payload.commitment_tree).map_err(
            |err| {
                Error::Other(format!(
                    "Could not deserialize the commitment tree borsh data at \
                     height {height}: {err}"
                ))
            },
        )
    }

    async fn fetch_tx_notes_map(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<BTreeMap<IndexedTx, usize>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Note {
            // masp_tx_index: u64,
            note_position: usize,
            block_index: u32,
            block_height: u64,
        }

        #[derive(Deserialize)]
        struct Response {
            notes_map: Vec<Note>,
        }

        let response = self
            .client
            .get(self.endpoint("/notes-map"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch notes map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch notes map at height {height}: {err}"
            )));
        }
        let payload: Response = response.json().await.map_err(|err| {
            Error::Other(format!(
                "Could not deserialize the notes map JSON response at height \
                 {height}: {err}"
            ))
        })?;

        Ok(payload
            .notes_map
            .into_iter()
            .map(
                |Note {
                     block_index,
                     block_height,
                     note_position,
                 }| {
                    (
                        IndexedTx {
                            index: TxIndex(block_index),
                            height: BlockHeight(block_height),
                        },
                        note_position,
                    )
                },
            )
            .collect())
    }

    async fn fetch_witness_map(
        &self,
        BlockHeight(height): BlockHeight,
    ) -> Result<HashMap<usize, IncrementalWitness<Node>>, Error> {
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct Witness {
            bytes: Vec<u8>,
            index: usize,
        }

        #[derive(Deserialize)]
        struct WitnessMapResponse {
            witnesses: Vec<Witness>,
        }

        let response = self
            .client
            .get(self.endpoint("/witness-map"))
            .keep_alive()
            .query(&[("height", height)])
            .send()
            .await
            .map_err(|err| {
                Error::Other(format!(
                    "Failed to fetch witness map at height {height}: {err}"
                ))
            })?;
        if !response.status().is_success() {
            let err = Self::get_server_error(response).await?;
            return Err(Error::Other(format!(
                "Failed to fetch witness map at height {height}: {err}"
            )));
        }
        let payload: WitnessMapResponse =
            response.json().await.map_err(|err| {
                Error::Other(format!(
                    "Could not deserialize the witness map JSON response at \
                     height {height}: {err}"
                ))
            })?;

        payload.witnesses.into_iter().try_fold(
            HashMap::new(),
            |mut accum, Witness { index, bytes }| {
                let witness = BorshDeserialize::try_from_slice(&bytes)
                    .map_err(|err| {
                        Error::Other(format!(
                            "Could not deserialize the witness borsh data at \
                             height {height}: {err}"
                        ))
                    })?;
                accum.insert(index, witness);
                Ok(accum)
            },
        )
    }
}

/// Given a block height range we wish to request and a cache of fetched block
/// heights, returns the set of sub-ranges we need to request so that all blocks
/// in the inclusive range `[from, to]` get cached.
pub fn blocks_left_to_fetch(
    from: BlockHeight,
    to: BlockHeight,
    fetched: &Fetched,
) -> Vec<[BlockHeight; 2]> {
    const ZERO: BlockHeight = BlockHeight(0);

    if from > to {
        panic!("Empty range passed to `blocks_left_to_fetch`, [{from}, {to}]");
    }
    if from == ZERO || to == ZERO {
        panic!("Block height values start at 1");
    }

    let mut to_fetch = Vec::with_capacity((to.0 - from.0 + 1) as usize);
    let mut current_from = from;
    let mut need_to_fetch = true;

    for height in (from.0..=to.0).map(BlockHeight) {
        let height_in_cache = fetched.contains_height(height);

        // cross an upper gap boundary
        if need_to_fetch && height_in_cache {
            if height > current_from {
                to_fetch.push([
                    current_from,
                    height.checked_sub(1).expect("Height is greater than zero"),
                ]);
            }
            need_to_fetch = false;
        } else if !need_to_fetch && !height_in_cache {
            // cross a lower gap boundary
            current_from = height;
            need_to_fetch = true;
        }
    }
    if need_to_fetch {
        to_fetch.push([current_from, to]);
    }
    to_fetch
}

/// An enum to indicate how to track progress depending on
/// whether sync is currently fetch or scanning blocks.
#[derive(Debug, Copy, Clone)]
pub enum ProgressType {
    /// Fetch
    Fetch,
    /// Scan
    Scan,
}

/// A peekable iterator interface
pub trait PeekableIter<I> {
    /// Peek at next element
    fn peek(&mut self) -> Option<&I>;

    /// get next element
    fn next(&mut self) -> Option<I>;
}

impl<I, J> PeekableIter<J> for std::iter::Peekable<I>
where
    I: Iterator<Item = J>,
{
    fn peek(&mut self) -> Option<&J> {
        self.peek()
    }

    fn next(&mut self) -> Option<J> {
        <Self as Iterator>::next(self)
    }
}

/// This trait keeps track of how much progress the
/// shielded sync algorithm has made relative to the inputs.
///
/// It should track how much has been fetched and scanned and
/// whether the fetching has been finished.
///
/// Additionally, it has access to IO in case the struct implementing
/// this trait wishes to log this progress.
pub trait ProgressTracker<IO: Io> {
    /// Get an IO handle
    fn io(&self) -> &IO;

    /// Return an iterator to fetched shielded transfers
    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>;

    /// Return an iterator over MASP transactions to be scanned
    fn scan<I>(
        &self,
        items: I,
    ) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: Iterator<Item = IndexedNoteEntry> + Send;

    /// The number of blocks that need to be fetched
    fn left_to_fetch(&self) -> usize;
}

/// The default type for tracking the progress of shielded-sync.
#[derive(Debug, Clone)]
pub struct DefaultTracker<'io, IO: Io> {
    io: &'io IO,
    progress: Arc<Mutex<IterProgress>>,
}

impl<'io, IO: Io> DefaultTracker<'io, IO> {
    /// New [`DefaultTracker`]
    pub fn new(io: &'io IO) -> Self {
        Self {
            io,
            progress: Arc::new(Mutex::new(Default::default())),
        }
    }
}

#[derive(Default, Copy, Clone, Debug)]
pub(in crate::masp) struct IterProgress {
    pub index: usize,
    pub length: usize,
}

pub(in crate::masp) struct DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    pub inner: I,
    pub progress: Arc<Mutex<IterProgress>>,
    pub peeked: Option<u64>,
}

impl<I> PeekableIter<u64> for DefaultFetchIterator<I>
where
    I: Iterator<Item = u64>,
{
    fn peek(&mut self) -> Option<&u64> {
        if self.peeked.is_none() {
            self.peeked = self.inner.next();
        }
        self.peeked.as_ref()
    }

    fn next(&mut self) -> Option<u64> {
        self.peek();
        let item = self.peeked.take()?;
        let mut locked = self.progress.lock().unwrap();
        locked.index += 1;
        Some(item)
    }
}

impl<'io, IO: Io> ProgressTracker<IO> for DefaultTracker<'io, IO> {
    fn io(&self) -> &IO {
        self.io
    }

    fn fetch<I>(&self, items: I) -> impl PeekableIter<u64>
    where
        I: Iterator<Item = u64>,
    {
        {
            let mut locked = self.progress.lock().unwrap();
            locked.length = items.size_hint().0;
        }
        DefaultFetchIterator {
            inner: items,
            progress: self.progress.clone(),
            peeked: None,
        }
    }

    fn scan<I>(&self, items: I) -> impl Iterator<Item = IndexedNoteEntry> + Send
    where
        I: IntoIterator<Item = IndexedNoteEntry>,
    {
        let items: Vec<_> = items.into_iter().collect();
        items.into_iter()
    }

    fn left_to_fetch(&self) -> usize {
        let locked = self.progress.lock().unwrap();
        locked.length - locked.index
    }
}
