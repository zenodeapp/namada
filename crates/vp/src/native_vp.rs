#![allow(clippy::assign_op_pattern)]
//! Native validity predicate interface associated with internal accounts such
//! as the PoS and IBC modules.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;

use namada_core::address::Address;
use namada_core::borsh::BorshDeserialize;
use namada_core::hash::Hash;
use namada_core::storage::Epochs;
use namada_core::{borsh, storage};
use namada_events::{Event, EventType};
use namada_gas::{GasMetering, VpGasMeter};
use namada_state as state;
use namada_state::prefix_iter::PrefixIterators;
use namada_state::{
    BlockHeight, Epoch, Header, Key, ResultExt, StorageRead, StorageResult,
    TxIndex,
};
use namada_tx::{BatchedTxRef, Tx, TxCommitments};
pub use namada_vp_env::VpEnv;
use state::StateRead;

use super::vp_host_fns;

/// Possible error in a native VP host function call
/// The `state::StorageError` may wrap the `vp_host_fns::RuntimeError`
/// and can be extended with other custom errors when using `trait VpEnv`.
pub type Error = state::StorageError;

/// A native VP module should implement its validation logic using this trait.
pub trait NativeVp<'a> {
    /// Error type for the methods' results.
    type Error: std::error::Error;

    /// Run the validity predicate
    fn validate_tx(
        &'a self,
        batched_tx: &BatchedTxRef<'_>,
        keys_changed: &BTreeSet<Key>,
        verifiers: &BTreeSet<Address>,
    ) -> std::result::Result<(), Self::Error>;
}

/// A validity predicate's host context.
///
/// This is similar to [`crate::vm::host_env::VpCtx`], but without the VM
/// wrapper types and `eval_runner` field. The references must not be changed
/// when [`Ctx`] is mutable.
#[derive(Debug)]
pub struct Ctx<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// The address of the account that owns the VP
    pub address: &'a Address,
    /// Storage prefix iterators.
    pub iterators: RefCell<PrefixIterators<'a, <S as StateRead>::D>>,
    /// VP gas meter.
    pub gas_meter: &'a RefCell<VpGasMeter>,
    /// Read-only state access.
    pub state: &'a S,
    /// The transaction
    pub tx: &'a Tx,
    /// The commitments in the transaction
    pub cmt: &'a TxCommitments,
    /// The transaction index is used to obtain the shielded transaction's
    /// parent
    pub tx_index: &'a TxIndex,
    /// The storage keys that have been changed. Used for calls to `eval`.
    pub keys_changed: &'a BTreeSet<Key>,
    /// The verifiers whose validity predicates should be triggered. Used for
    /// calls to `eval`.
    pub verifiers: &'a BTreeSet<Address>,
    /// VP WASM compilation cache
    pub vp_wasm_cache: CA,
    /// VP evaluator type
    pub eval: PhantomData<EVAL>,
}

/// A Validity predicate runner for calls from the [`vp_eval`] function.
pub trait VpEvaluator<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    /// Evaluate a given validity predicate code with the given input data.
    /// Currently, we can only evaluate VPs using WASM runner with WASM memory.
    ///
    /// Invariant: Calling `VpEvalRunner::eval` from the VP is synchronous as it
    /// shares mutable access to the host context with the VP.
    fn eval(
        ctx: &Ctx<'a, S, CA, EVAL>,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> StorageResult<()>;
}

/// Read access to the prior storage (state before tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPreStorageRead<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    pub ctx: &'view Ctx<'a, S, CA, EVAL>,
}

/// Read access to the posterior storage (state after tx execution) via
/// [`trait@StorageRead`].
#[derive(Debug)]
pub struct CtxPostStorageRead<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
{
    ctx: &'view Ctx<'a, S, CA, EVAL>,
}

impl<'a, S, CA, EVAL> Ctx<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    /// Initialize a new context for native VP call
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        address: &'a Address,
        state: &'a S,
        tx: &'a Tx,
        cmt: &'a TxCommitments,
        tx_index: &'a TxIndex,
        gas_meter: &'a RefCell<VpGasMeter>,
        keys_changed: &'a BTreeSet<Key>,
        verifiers: &'a BTreeSet<Address>,
        vp_wasm_cache: CA,
    ) -> Self {
        Self {
            address,
            state,
            iterators: RefCell::new(PrefixIterators::default()),
            gas_meter,
            tx,
            cmt,
            tx_index,
            keys_changed,
            verifiers,
            vp_wasm_cache,
            eval: PhantomData,
        }
    }

    /// Read access to the prior storage (state before tx execution)
    /// via [`trait@StorageRead`].
    pub fn pre<'view>(
        &'view self,
    ) -> CtxPreStorageRead<'view, 'a, S, CA, EVAL> {
        CtxPreStorageRead { ctx: self }
    }

    /// Read access to the posterior storage (state after tx execution)
    /// via [`trait@StorageRead`].
    pub fn post<'view>(
        &'view self,
    ) -> CtxPostStorageRead<'view, 'a, S, CA, EVAL> {
        CtxPostStorageRead { ctx: self }
    }
}

impl<'view, 'a: 'view, S, CA, EVAL> StorageRead
    for CtxPreStorageRead<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    type PrefixIter<'iter> = state::PrefixIter<'iter,<S as StateRead>:: D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> Result<Option<Vec<u8>>, state::StorageError> {
        vp_host_fns::read_pre(self.ctx.gas_meter, self.ctx.state, key)
            .into_storage_result()
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, state::StorageError> {
        vp_host_fns::has_key_pre(self.ctx.gas_meter, self.ctx.state, key)
            .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, state::StorageError> {
        vp_host_fns::iter_prefix_pre(
            self.ctx.gas_meter,
            self.ctx.state.write_log(),
            self.ctx.state.db(),
            prefix,
        )
        .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, state::StorageError> {
        vp_host_fns::iter_next::<<S as StateRead>::D>(self.ctx.gas_meter, iter)
            .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, state::StorageError> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, state::StorageError> {
        self.ctx.get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, state::StorageError> {
        self.ctx.get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch, state::StorageError> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, state::StorageError> {
        self.ctx.get_tx_index().into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, state::StorageError> {
        self.ctx.get_native_token()
    }

    fn get_pred_epochs(&self) -> StorageResult<Epochs> {
        self.ctx.get_pred_epochs()
    }
}

impl<'view, 'a: 'view, S, CA, EVAL> StorageRead
    for CtxPostStorageRead<'view, 'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    type PrefixIter<'iter> = state::PrefixIter<'iter, <S as StateRead>::D> where Self: 'iter;

    fn read_bytes(
        &self,
        key: &storage::Key,
    ) -> Result<Option<Vec<u8>>, state::StorageError> {
        vp_host_fns::read_post(self.ctx.gas_meter, self.ctx.state, key)
            .into_storage_result()
    }

    fn has_key(&self, key: &storage::Key) -> Result<bool, state::StorageError> {
        vp_host_fns::has_key_post(self.ctx.gas_meter, self.ctx.state, key)
            .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &storage::Key,
    ) -> Result<Self::PrefixIter<'iter>, state::StorageError> {
        vp_host_fns::iter_prefix_post(
            self.ctx.gas_meter,
            self.ctx.state.write_log(),
            self.ctx.state.db(),
            prefix,
        )
        .into_storage_result()
    }

    // ---- Methods below are implemented in `self.ctx`, because they are
    //      the same in `pre/post` ----

    fn iter_next<'iter>(
        &'iter self,
        iter: &mut Self::PrefixIter<'iter>,
    ) -> Result<Option<(String, Vec<u8>)>, state::StorageError> {
        vp_host_fns::iter_next::<<S as StateRead>::D>(self.ctx.gas_meter, iter)
            .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, state::StorageError> {
        self.ctx.get_chain_id()
    }

    fn get_block_height(&self) -> Result<BlockHeight, state::StorageError> {
        self.ctx.get_block_height()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, state::StorageError> {
        self.ctx.get_block_header(height)
    }

    fn get_block_epoch(&self) -> Result<Epoch, state::StorageError> {
        self.ctx.get_block_epoch()
    }

    fn get_tx_index(&self) -> Result<TxIndex, state::StorageError> {
        self.ctx.get_tx_index().into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, state::StorageError> {
        Ok(self.ctx.state.in_mem().native_token.clone())
    }

    fn get_pred_epochs(&self) -> StorageResult<Epochs> {
        self.ctx.get_pred_epochs()
    }
}

impl<'view, 'a: 'view, S, CA, EVAL> VpEnv<'view> for Ctx<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    type Post = CtxPostStorageRead<'view, 'a, S, CA, EVAL>;
    type Pre = CtxPreStorageRead<'view, 'a, S, CA, EVAL>;
    type PrefixIter<'iter> = state::PrefixIter<'iter, <S as StateRead>::D> where Self: 'iter;

    fn pre(&'view self) -> Self::Pre {
        CtxPreStorageRead { ctx: self }
    }

    fn post(&'view self) -> Self::Post {
        CtxPostStorageRead { ctx: self }
    }

    fn read_temp<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError> {
        vp_host_fns::read_temp(self.gas_meter, self.state, key)
            .map(|data| data.and_then(|t| T::try_from_slice(&t[..]).ok()))
            .into_storage_result()
    }

    fn read_bytes_temp(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, state::StorageError> {
        vp_host_fns::read_temp(self.gas_meter, self.state, key)
            .into_storage_result()
    }

    fn get_chain_id(&self) -> Result<String, state::StorageError> {
        vp_host_fns::get_chain_id(self.gas_meter, self.state)
            .into_storage_result()
    }

    fn get_block_height(&self) -> Result<BlockHeight, state::StorageError> {
        vp_host_fns::get_block_height(self.gas_meter, self.state)
            .into_storage_result()
    }

    fn get_block_header(
        &self,
        height: BlockHeight,
    ) -> Result<Option<Header>, state::StorageError> {
        vp_host_fns::get_block_header(self.gas_meter, self.state, height)
            .into_storage_result()
    }

    fn get_block_epoch(&self) -> Result<Epoch, state::StorageError> {
        vp_host_fns::get_block_epoch(self.gas_meter, self.state)
            .into_storage_result()
    }

    fn get_tx_index(&self) -> Result<TxIndex, state::StorageError> {
        vp_host_fns::get_tx_index(self.gas_meter, self.tx_index)
            .into_storage_result()
    }

    fn get_native_token(&self) -> Result<Address, state::StorageError> {
        vp_host_fns::get_native_token(self.gas_meter, self.state)
            .into_storage_result()
    }

    fn get_pred_epochs(&self) -> StorageResult<Epochs> {
        vp_host_fns::get_pred_epochs(self.gas_meter, self.state)
            .into_storage_result()
    }

    fn get_events(
        &self,
        event_type: &EventType,
    ) -> Result<Vec<Event>, state::StorageError> {
        vp_host_fns::get_events(
            self.gas_meter,
            self.state,
            event_type.to_string(),
        )
        .into_storage_result()
    }

    fn iter_prefix<'iter>(
        &'iter self,
        prefix: &Key,
    ) -> Result<Self::PrefixIter<'iter>, state::StorageError> {
        vp_host_fns::iter_prefix_pre(
            self.gas_meter,
            self.state.write_log(),
            self.state.db(),
            prefix,
        )
        .into_storage_result()
    }

    fn eval(
        &self,
        vp_code_hash: Hash,
        input_data: BatchedTxRef<'_>,
    ) -> StorageResult<()> {
        EVAL::eval(self, vp_code_hash, input_data)
    }

    fn charge_gas(&self, used_gas: u64) -> Result<(), state::StorageError> {
        self.gas_meter.borrow_mut().consume(used_gas).map_err(|_| {
            Error::SimpleMessage("Gas limit exceeded in native vp")
        })
    }

    fn get_tx_code_hash(&self) -> Result<Option<Hash>, state::StorageError> {
        vp_host_fns::get_tx_code_hash(
            self.gas_meter,
            &self.tx.batch_ref_tx(self.cmt),
        )
        .into_storage_result()
    }

    fn read_pre<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError> {
        self.pre().read(key).map_err(Into::into)
    }

    fn read_bytes_pre(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, state::StorageError> {
        self.pre().read_bytes(key).map_err(Into::into)
    }

    fn read_post<T: borsh::BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError> {
        self.post().read(key).map_err(Into::into)
    }

    fn read_bytes_post(
        &self,
        key: &Key,
    ) -> Result<Option<Vec<u8>>, state::StorageError> {
        self.post().read_bytes(key).map_err(Into::into)
    }

    fn has_key_pre(&self, key: &Key) -> Result<bool, state::StorageError> {
        self.pre().has_key(key).map_err(Into::into)
    }

    fn has_key_post(&self, key: &Key) -> Result<bool, state::StorageError> {
        self.post().has_key(key).map_err(Into::into)
    }
}

impl<'a, S, CA, EVAL> namada_tx::action::Read for Ctx<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    type Err = Error;

    fn read_temp<T: BorshDeserialize>(
        &self,
        key: &storage::Key,
    ) -> Result<Option<T>, Self::Err> {
        VpEnv::read_temp(self, key)
    }
}

/// A convenience trait for reading and automatically deserializing a value from
/// storage
pub trait StorageReader {
    /// Storage read prior state (before tx execution). It will try to read from
    /// the storage.
    fn read_pre_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError>;

    /// Storage read posterior state (after tx execution). It will try to read
    /// from the write log first and if no entry found then from the
    /// storage.
    fn read_post_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError>;

    /// Calls `read_pre_value`, and returns an error on `Ok(None)`.
    fn must_read_pre_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<T, state::StorageError> {
        match self.read_pre_value(key) {
            Ok(None) => Err(state::StorageError::AllocMessage(format!(
                "Expected a value to be present in the key {key}"
            ))),
            Ok(Some(x)) => Ok(x),
            Err(err) => Err(err),
        }
    }

    /// Calls `read_post_value`, and returns an error on `Ok(None)`.
    fn must_read_post_value<T: BorshDeserialize>(
        &self,
        key: &Key,
    ) -> Result<T, state::StorageError> {
        match self.read_post_value(key) {
            Ok(None) => Err(state::StorageError::AllocMessage(format!(
                "Expected a value to be present in the key {key}"
            ))),
            Ok(Some(x)) => Ok(x),
            Err(err) => Err(err),
        }
    }
}

impl<'a, S, CA, EVAL> StorageReader for &Ctx<'a, S, CA, EVAL>
where
    S: 'static + StateRead,
    EVAL: 'static + VpEvaluator<'a, S, CA, EVAL>,
    CA: 'static + Clone,
{
    /// Helper function. After reading posterior state,
    /// borsh deserialize to specified type
    fn read_post_value<T>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError>
    where
        T: BorshDeserialize,
    {
        Ctx::read_post(self, key)
    }

    /// Helper function. After reading prior state,
    /// borsh deserialize to specified type
    fn read_pre_value<T>(
        &self,
        key: &Key,
    ) -> Result<Option<T>, state::StorageError>
    where
        T: BorshDeserialize,
    {
        Ctx::read_pre(self, key)
    }
}

#[cfg(any(test, feature = "testing"))]
pub(super) mod testing {
    use namada_core::collections::HashMap;

    use super::*;

    #[derive(Debug, Default)]
    pub(in super::super) struct FakeStorageReader {
        pre: HashMap<Key, Vec<u8>>,
        post: HashMap<Key, Vec<u8>>,
    }

    impl StorageReader for FakeStorageReader {
        fn read_pre_value<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> Result<Option<T>, state::StorageError> {
            self.pre
                .get(key)
                .map(|bytes| T::try_from_slice(bytes).into_storage_result())
                .transpose()
        }

        fn read_post_value<T: BorshDeserialize>(
            &self,
            key: &Key,
        ) -> Result<Option<T>, state::StorageError> {
            self.post
                .get(key)
                .map(|bytes| T::try_from_slice(bytes).into_storage_result())
                .transpose()
        }
    }
}
