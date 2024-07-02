//! IBC library code

#![doc(html_favicon_url = "https://dev.namada.net/master/favicon.png")]
#![doc(html_logo_url = "https://dev.namada.net/master/rustdoc-logo.png")]
#![deny(rustdoc::broken_intra_doc_links)]
#![deny(rustdoc::private_intra_doc_links)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    clippy::cast_sign_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::arithmetic_side_effects,
    clippy::dbg_macro,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod actions;
pub mod context;
pub mod event;
mod msg;
mod nft;
pub mod parameters;
pub mod storage;
pub mod trace;
pub mod vp;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::rc::Rc;

pub use actions::transfer_over_ibc;
use apps::transfer::types::packet::PacketData;
use apps::transfer::types::PORT_ID_STR;
use borsh::BorshDeserialize;
pub use context::common::IbcCommonContext;
pub use context::nft_transfer::NftTransferContext;
pub use context::nft_transfer_mod::NftTransferModule;
use context::router::IbcRouter;
pub use context::storage::{IbcStorageContext, ProofSpec};
pub use context::token_transfer::TokenTransferContext;
pub use context::transfer_mod::{ModuleWrapper, TransferModule};
use context::IbcContext;
pub use context::ValidationParams;
use ibc::apps::nft_transfer::handler::{
    send_nft_transfer_execute, send_nft_transfer_validate,
};
use ibc::apps::nft_transfer::types::error::NftTransferError;
use ibc::apps::nft_transfer::types::msgs::transfer::MsgTransfer as IbcMsgNftTransfer;
use ibc::apps::nft_transfer::types::{
    ack_success_b64, is_receiver_chain_source as is_nft_receiver_chain_source,
    PrefixedClassId, TokenId, TracePrefix as NftTracePrefix,
};
use ibc::apps::transfer::handler::{
    send_transfer_execute, send_transfer_validate,
};
use ibc::apps::transfer::types::error::TokenTransferError;
use ibc::apps::transfer::types::msgs::transfer::MsgTransfer as IbcMsgTransfer;
use ibc::apps::transfer::types::{is_receiver_chain_source, TracePrefix};
use ibc::core::channel::types::acknowledgement::{
    Acknowledgement, AcknowledgementStatus,
};
use ibc::core::channel::types::commitment::compute_ack_commitment;
use ibc::core::channel::types::msgs::{
    MsgRecvPacket as IbcMsgRecvPacket, PacketMsg,
};
use ibc::core::channel::types::timeout::TimeoutHeight;
use ibc::core::entrypoint::{execute, validate};
use ibc::core::handler::types::error::ContextError;
use ibc::core::handler::types::events::Error as RawIbcEventError;
use ibc::core::handler::types::msgs::MsgEnvelope;
use ibc::core::host::types::error::IdentifierError;
use ibc::core::host::types::identifiers::{ChannelId, PortId, Sequence};
use ibc::core::router::types::error::RouterError;
use ibc::primitives::proto::Any;
pub use ibc::*;
use masp_primitives::transaction::Transaction as MaspTransaction;
pub use msg::*;
use namada_core::address::{self, Address};
use namada_core::arith::{checked, CheckedAdd, CheckedSub};
use namada_core::ibc::apps::nft_transfer::types::packet::PacketData as NftPacketData;
use namada_core::ibc::core::channel::types::commitment::{
    compute_packet_commitment, AcknowledgementCommitment, PacketCommitment,
};
use namada_core::masp::{addr_taddr, ibc_taddr, TAddrData};
use namada_core::token::Amount;
use namada_events::EmitEvents;
use namada_state::{
    DBIter, Key, ResultExt, State, StorageError, StorageHasher, StorageRead,
    StorageWrite, WlState, DB,
};
use namada_systems::ibc::ChangedBalances;
use namada_token::transaction::components::ValueSum;
use namada_token::Transfer;
pub use nft::*;
use primitives::Timestamp;
use prost::Message;
use thiserror::Error;
use trace::{convert_to_address, ibc_trace_for_nft, is_sender_chain_source};

use crate::storage::{
    channel_counter_key, client_counter_key, connection_counter_key,
    deposit_prefix, withdraw_prefix,
};

/// The event type defined in ibc-rs for receiving a token
pub const EVENT_TYPE_PACKET: &str = "fungible_token_packet";
/// The event type defined in ibc-rs for receiving an NFT
pub const EVENT_TYPE_NFT_PACKET: &str = "non_fungible_token_packet";
/// The escrow address for IBC transfer
pub const IBC_ESCROW_ADDRESS: Address = address::IBC;

#[allow(missing_docs)]
#[derive(Error, Debug)]
pub enum Error {
    #[error("IBC event error: {0}")]
    IbcEvent(RawIbcEventError),
    #[error("Decoding IBC data error")]
    DecodingData,
    #[error("Decoding message error: {0}")]
    DecodingMessage(RouterError),
    #[error("IBC context error: {0}")]
    Context(Box<ContextError>),
    #[error("IBC token transfer error: {0}")]
    TokenTransfer(TokenTransferError),
    #[error("IBC NFT transfer error: {0}")]
    NftTransfer(NftTransferError),
    #[error("Trace error: {0}")]
    Trace(String),
    #[error("Invalid chain ID: {0}")]
    ChainId(IdentifierError),
    #[error("Verifier insertion error: {0}")]
    Verifier(namada_storage::Error),
}

struct IbcTransferInfo {
    src_port_id: PortId,
    src_channel_id: ChannelId,
    timeout_height: TimeoutHeight,
    timeout_timestamp: Timestamp,
    packet_data: Vec<u8>,
    ibc_traces: Vec<String>,
    amount: Amount,
    receiver: String,
}

impl TryFrom<IbcMsgTransfer> for IbcTransferInfo {
    type Error = namada_storage::Error;

    fn try_from(
        message: IbcMsgTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(namada_storage::Error::new)?;
        let ibc_traces = vec![message.packet_data.token.denom.to_string()];
        let amount = message
            .packet_data
            .token
            .amount
            .try_into()
            .into_storage_result()?;
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount,
            receiver,
        })
    }
}

impl TryFrom<IbcMsgNftTransfer> for IbcTransferInfo {
    type Error = namada_storage::Error;

    fn try_from(
        message: IbcMsgNftTransfer,
    ) -> std::result::Result<Self, Self::Error> {
        let packet_data = serde_json::to_vec(&message.packet_data)
            .map_err(namada_storage::Error::new)?;
        let ibc_traces = message
            .packet_data
            .token_ids
            .0
            .iter()
            .map(|token_id| {
                ibc_trace_for_nft(&message.packet_data.class_id, token_id)
            })
            .collect();
        let receiver = message.packet_data.receiver.to_string();
        Ok(Self {
            src_port_id: message.port_id_on_a,
            src_channel_id: message.chan_id_on_a,
            timeout_height: message.timeout_height_on_b,
            timeout_timestamp: message.timeout_timestamp_on_b,
            packet_data,
            ibc_traces,
            amount: Amount::from_u64(1),
            receiver,
        })
    }
}

/// IBC storage `Keys/Read/Write` implementation
#[derive(Debug)]
pub struct Store<S>(PhantomData<S>);

impl<S> namada_systems::ibc::Read<S> for Store<S>
where
    S: StorageRead,
{
    type Err = namada_storage::Error;

    fn try_extract_masp_tx_from_envelope(
        tx_data: &[u8],
    ) -> Result<Option<masp_primitives::transaction::Transaction>, Self::Err>
    {
        let msg = decode_message(tx_data).into_storage_result().ok();
        let tx = if let Some(IbcMessage::Envelope(ref envelope)) = msg {
            Some(extract_masp_tx_from_envelope(envelope).ok_or_else(|| {
                namada_storage::Error::new_const(
                    "Missing MASP transaction in IBC message",
                )
            })?)
        } else {
            None
        };
        Ok(tx)
    }

    fn apply_ibc_packet(
        storage: &S,
        tx_data: &[u8],
        mut acc: ChangedBalances,
        keys_changed: &BTreeSet<namada_core::storage::Key>,
    ) -> Result<ChangedBalances, Self::Err> {
        let msg = decode_message(tx_data).into_storage_result().ok();
        match msg {
            None => {}
            // This event is emitted on the sender
            Some(IbcMessage::Transfer(msg)) => {
                // Get the packet commitment from post-storage that corresponds
                // to this event
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                acc.decoder.insert(ibc_taddr(receiver), addr);
                acc = apply_transfer_msg(
                    storage,
                    acc,
                    &ibc_transfer,
                    keys_changed,
                )?;
            }
            Some(IbcMessage::NftTransfer(msg)) => {
                let ibc_transfer = IbcTransferInfo::try_from(msg.message)?;
                let receiver = ibc_transfer.receiver.clone();
                let addr = TAddrData::Ibc(receiver.clone());
                acc.decoder.insert(ibc_taddr(receiver), addr);
                acc = apply_transfer_msg(
                    storage,
                    acc,
                    &ibc_transfer,
                    keys_changed,
                )?;
            }
            // This event is emitted on the receiver
            Some(IbcMessage::Envelope(envelope)) => {
                if let MsgEnvelope::Packet(PacketMsg::Recv(msg)) = *envelope {
                    if msg.packet.port_id_on_b.as_str() == PORT_ID_STR {
                        let packet_data = serde_json::from_slice::<PacketData>(
                            &msg.packet.data,
                        )
                        .map_err(namada_storage::Error::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        acc.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_denom = packet_data.token.denom.to_string();
                        let amount = packet_data
                            .token
                            .amount
                            .try_into()
                            .into_storage_result()?;
                        acc = apply_recv_msg(
                            storage,
                            acc,
                            &msg,
                            vec![ibc_denom],
                            amount,
                            keys_changed,
                        )?;
                    } else {
                        let packet_data =
                            serde_json::from_slice::<NftPacketData>(
                                &msg.packet.data,
                            )
                            .map_err(namada_storage::Error::new)?;
                        let receiver = packet_data.receiver.to_string();
                        let addr = TAddrData::Ibc(receiver.clone());
                        acc.decoder.insert(ibc_taddr(receiver), addr);
                        let ibc_traces = packet_data
                            .token_ids
                            .0
                            .iter()
                            .map(|token_id| {
                                ibc_trace_for_nft(
                                    &packet_data.class_id,
                                    token_id,
                                )
                            })
                            .collect();
                        acc = apply_recv_msg(
                            storage,
                            acc,
                            &msg,
                            ibc_traces,
                            Amount::from_u64(1),
                            keys_changed,
                        )?;
                    }
                }
            }
        }
        Ok(acc)
    }
}

fn check_ibc_transfer<S>(
    storage: &S,
    ibc_transfer: &IbcTransferInfo,
    keys_changed: &BTreeSet<Key>,
) -> namada_storage::Result<()>
where
    S: StorageRead,
{
    let IbcTransferInfo {
        src_port_id,
        src_channel_id,
        timeout_height,
        timeout_timestamp,
        packet_data,
        ..
    } = ibc_transfer;
    let sequence =
        get_last_sequence_send(storage, src_port_id, src_channel_id)?;
    let commitment_key =
        storage::commitment_key(src_port_id, src_channel_id, sequence);

    if !keys_changed.contains(&commitment_key) {
        return Err(namada_storage::Error::new_alloc(format!(
            "Expected IBC transfer didn't happen: Port ID {src_port_id}, \
             Channel ID {src_channel_id}, Sequence {sequence}"
        )));
    }

    // The commitment is also validated in IBC VP. Make sure that for when
    // IBC VP isn't triggered.
    let actual: PacketCommitment = storage
        .read_bytes(&commitment_key)?
        .ok_or(namada_storage::Error::new_alloc(format!(
            "Packet commitment doesn't exist: Port ID  {src_port_id}, Channel \
             ID {src_channel_id}, Sequence {sequence}"
        )))?
        .into();
    let expected = compute_packet_commitment(
        packet_data,
        timeout_height,
        timeout_timestamp,
    );
    if actual != expected {
        return Err(namada_storage::Error::new_alloc(format!(
            "Packet commitment mismatched: Port ID {src_port_id}, Channel ID \
             {src_channel_id}, Sequence {sequence}"
        )));
    }

    Ok(())
}

fn check_packet_receiving(
    msg: &IbcMsgRecvPacket,
    keys_changed: &BTreeSet<Key>,
) -> namada_storage::Result<()> {
    let receipt_key = storage::receipt_key(
        &msg.packet.port_id_on_b,
        &msg.packet.chan_id_on_b,
        msg.packet.seq_on_a,
    );
    if !keys_changed.contains(&receipt_key) {
        return Err(namada_storage::Error::new_alloc(format!(
            "The packet has not been received: Port ID  {}, Channel ID {}, \
             Sequence {}",
            msg.packet.port_id_on_b,
            msg.packet.chan_id_on_b,
            msg.packet.seq_on_a,
        )));
    }
    Ok(())
}

// Apply the given transfer message to the changed balances structure
fn apply_transfer_msg<S>(
    storage: &S,
    mut acc: ChangedBalances,
    ibc_transfer: &IbcTransferInfo,
    keys_changed: &BTreeSet<Key>,
) -> namada_storage::Result<ChangedBalances>
where
    S: StorageRead,
{
    check_ibc_transfer(storage, ibc_transfer, keys_changed)?;

    let IbcTransferInfo {
        ibc_traces,
        src_port_id,
        src_channel_id,
        amount,
        receiver,
        ..
    } = ibc_transfer;

    let receiver = ibc_taddr(receiver.clone());
    for ibc_trace in ibc_traces {
        let token = convert_to_address(ibc_trace).into_storage_result()?;
        let delta = ValueSum::from_pair(token, *amount);
        // If there is a transfer to the IBC account, then deduplicate the
        // balance increase since we already accounted for it above
        if is_sender_chain_source(ibc_trace, src_port_id, src_channel_id) {
            let ibc_taddr = addr_taddr(address::IBC);
            let post_entry = acc
                .post
                .get(&ibc_taddr)
                .cloned()
                .unwrap_or(ValueSum::zero());
            acc.post.insert(
                ibc_taddr,
                checked!(post_entry - &delta)
                    .map_err(namada_storage::Error::new)?,
            );
        }
        // Record an increase to the balance of a specific IBC receiver
        let post_entry =
            acc.post.get(&receiver).cloned().unwrap_or(ValueSum::zero());
        acc.post.insert(
            receiver,
            checked!(post_entry + &delta)
                .map_err(namada_storage::Error::new)?,
        );
    }

    Ok(acc)
}

// Check if IBC message was received successfully in this state transition
fn is_receiving_success<S>(
    storage: &S,
    dst_port_id: &PortId,
    dst_channel_id: &ChannelId,
    sequence: Sequence,
) -> namada_storage::Result<bool>
where
    S: StorageRead,
{
    // Ensure that the event corresponds to the current changes to storage
    let ack_key = storage::ack_key(dst_port_id, dst_channel_id, sequence); // If the receive is a success, then the commitment is unique
    let succ_ack_commitment = compute_ack_commitment(
        &AcknowledgementStatus::success(ack_success_b64()).into(),
    );
    Ok(match storage.read_bytes(&ack_key)? {
        // Success happens only if commitment equals the above
        Some(value) => {
            AcknowledgementCommitment::from(value) == succ_ack_commitment
        }
        // Acknowledgement key non-existence is failure
        None => false,
    })
}

// Apply the given write acknowledge to the changed balances structure
fn apply_recv_msg<S>(
    storage: &S,
    mut acc: ChangedBalances,
    msg: &IbcMsgRecvPacket,
    ibc_traces: Vec<String>,
    amount: Amount,
    keys_changed: &BTreeSet<Key>,
) -> namada_storage::Result<ChangedBalances>
where
    S: StorageRead,
{
    check_packet_receiving(msg, keys_changed)?;

    // If the transfer was a failure, then enable funds to
    // be withdrawn from the IBC internal address
    if is_receiving_success(
        storage,
        &msg.packet.port_id_on_b,
        &msg.packet.chan_id_on_b,
        msg.packet.seq_on_a,
    )? {
        for ibc_trace in ibc_traces {
            // Get the received token
            let token = received_ibc_token(
                ibc_trace,
                &msg.packet.port_id_on_a,
                &msg.packet.chan_id_on_a,
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
            )
            .into_storage_result()?;
            let delta = ValueSum::from_pair(token.clone(), amount);
            // Enable funds to be taken from the IBC internal
            // address and be deposited elsewhere
            // Required for the IBC internal Address to release
            // funds
            let ibc_taddr = addr_taddr(address::IBC);
            let pre_entry =
                acc.pre.get(&ibc_taddr).cloned().unwrap_or(ValueSum::zero());
            acc.pre.insert(
                ibc_taddr,
                checked!(pre_entry + &delta)
                    .map_err(namada_storage::Error::new)?,
            );
        }
    }
    Ok(acc)
}

/// IBC actions to handle IBC operations
#[derive(Debug)]
pub struct IbcActions<'a, C>
where
    C: IbcCommonContext,
{
    ctx: IbcContext<C>,
    router: IbcRouter<'a>,
    verifiers: Rc<RefCell<BTreeSet<Address>>>,
}

impl<'a, C> IbcActions<'a, C>
where
    C: IbcCommonContext + Debug,
{
    /// Make new IBC actions
    pub fn new(
        ctx: Rc<RefCell<C>>,
        verifiers: Rc<RefCell<BTreeSet<Address>>>,
    ) -> Self {
        Self {
            ctx: IbcContext::new(ctx),
            router: IbcRouter::new(),
            verifiers,
        }
    }

    /// Add a transfer module to the router
    pub fn add_transfer_module(&mut self, module: impl ModuleWrapper + 'a) {
        self.router.add_transfer_module(module)
    }

    /// Set the validation parameters
    pub fn set_validation_params(&mut self, params: ValidationParams) {
        self.ctx.validation_params = params;
    }

    /// Execute according to the message in an IBC transaction or VP
    pub fn execute(
        &mut self,
        tx_data: &[u8],
    ) -> Result<(Option<Transfer>, Option<MaspTransaction>), Error> {
        let message = decode_message(tx_data)?;
        match &message {
            IbcMessage::Transfer(msg) => {
                let mut token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    self.verifiers.clone(),
                );
                self.insert_verifiers()?;
                send_transfer_execute(
                    &mut self.ctx,
                    &mut token_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::TokenTransfer)?;
                Ok((msg.transfer.clone(), None))
            }
            IbcMessage::NftTransfer(msg) => {
                let mut nft_transfer_ctx =
                    NftTransferContext::new(self.ctx.inner.clone());
                send_nft_transfer_execute(
                    &mut self.ctx,
                    &mut nft_transfer_ctx,
                    msg.message.clone(),
                )
                .map_err(Error::NftTransfer)?;
                Ok((msg.transfer.clone(), None))
            }
            IbcMessage::Envelope(envelope) => {
                execute(&mut self.ctx, &mut self.router, *envelope.clone())
                    .map_err(|e| Error::Context(Box::new(e)))?;
                // Extract MASP tx from the memo in the packet if needed
                let masp_tx = match &**envelope {
                    MsgEnvelope::Packet(packet_msg) => {
                        match packet_msg {
                            PacketMsg::Recv(msg) => {
                                if self.is_receiving_success(msg)? {
                                    extract_masp_tx_from_packet(
                                        &msg.packet,
                                        false,
                                    )
                                } else {
                                    None
                                }
                            }
                            PacketMsg::Ack(msg) => {
                                if is_ack_successful(&msg.acknowledgement)? {
                                    // No refund
                                    None
                                } else {
                                    extract_masp_tx_from_packet(
                                        &msg.packet,
                                        true,
                                    )
                                }
                            }
                            PacketMsg::Timeout(msg) => {
                                extract_masp_tx_from_packet(&msg.packet, true)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                Ok((None, masp_tx))
            }
        }
    }

    /// Check the result of receiving the packet by checking the packet
    /// acknowledgement
    pub fn is_receiving_success(
        &self,
        msg: &IbcMsgRecvPacket,
    ) -> Result<bool, Error> {
        let packet_ack = self
            .ctx
            .inner
            .borrow()
            .packet_ack(
                &msg.packet.port_id_on_b,
                &msg.packet.chan_id_on_b,
                msg.packet.seq_on_a,
            )
            .map_err(|e| Error::Context(Box::new(e)))?;
        let success_ack_commitment = compute_ack_commitment(
            &AcknowledgementStatus::success(ack_success_b64()).into(),
        );
        Ok(packet_ack == success_ack_commitment)
    }

    /// Validate according to the message in IBC VP
    pub fn validate(&self, tx_data: &[u8]) -> Result<(), Error> {
        // Use an empty verifiers set placeholder for validation, this is only
        // needed in actual txs to addresses whose VPs should be triggered
        let verifiers = Rc::new(RefCell::new(BTreeSet::<Address>::new()));

        let message = decode_message(tx_data)?;
        match message {
            IbcMessage::Transfer(msg) => {
                let token_transfer_ctx = TokenTransferContext::new(
                    self.ctx.inner.clone(),
                    verifiers.clone(),
                );
                self.insert_verifiers()?;
                send_transfer_validate(
                    &self.ctx,
                    &token_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::TokenTransfer)
            }
            IbcMessage::NftTransfer(msg) => {
                let nft_transfer_ctx =
                    NftTransferContext::new(self.ctx.inner.clone());
                send_nft_transfer_validate(
                    &self.ctx,
                    &nft_transfer_ctx,
                    msg.message,
                )
                .map_err(Error::NftTransfer)
            }
            IbcMessage::Envelope(envelope) => {
                validate(&self.ctx, &self.router, *envelope)
                    .map_err(|e| Error::Context(Box::new(e)))
            }
        }
    }

    fn insert_verifiers(&self) -> Result<(), Error> {
        let mut ctx = self.ctx.inner.borrow_mut();
        for verifier in self.verifiers.borrow().iter() {
            ctx.insert_verifier(verifier).map_err(Error::Verifier)?;
        }
        Ok(())
    }
}

fn is_ack_successful(ack: &Acknowledgement) -> Result<bool, Error> {
    let acknowledgement = serde_json::from_slice::<AcknowledgementStatus>(
        ack.as_ref(),
    )
    .map_err(|e| {
        Error::TokenTransfer(TokenTransferError::Other(format!(
            "Decoding the acknowledgement failed: {e}"
        )))
    })?;
    Ok(acknowledgement.is_successful())
}

/// Tries to decode transaction data to an `IbcMessage`
pub fn decode_message(tx_data: &[u8]) -> Result<IbcMessage, Error> {
    // ibc-rs message
    if let Ok(any_msg) = Any::decode(tx_data) {
        if let Ok(envelope) = MsgEnvelope::try_from(any_msg.clone()) {
            return Ok(IbcMessage::Envelope(Box::new(envelope)));
        }
        if let Ok(message) = IbcMsgTransfer::try_from(any_msg.clone()) {
            let msg = MsgTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::Transfer(msg));
        }
        if let Ok(message) = IbcMsgNftTransfer::try_from(any_msg) {
            let msg = MsgNftTransfer {
                message,
                transfer: None,
            };
            return Ok(IbcMessage::NftTransfer(msg));
        }
    }

    // Transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::Transfer(msg));
    }

    // NFT transfer message with `ShieldingTransfer`
    if let Ok(msg) = MsgNftTransfer::try_from_slice(tx_data) {
        return Ok(IbcMessage::NftTransfer(msg));
    }

    Err(Error::DecodingData)
}

/// Return the last sequence send
pub fn get_last_sequence_send<S: StorageRead>(
    storage: &S,
    port_id: &PortId,
    channel_id: &ChannelId,
) -> Result<Sequence, StorageError> {
    let seq_key = storage::next_sequence_send_key(port_id, channel_id);
    let next_seq: u64 =
        context::common::read_sequence(storage, &seq_key)?.into();
    if next_seq <= 1 {
        // No transfer heppened
        return Err(StorageError::new_alloc(format!(
            "No IBC transfer happened: Port ID {port_id}, Channel ID \
             {channel_id}",
        )));
    }
    Ok(checked!(next_seq - 1)?.into())
}

fn received_ibc_trace(
    base_trace: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<String, Error> {
    if *dest_port_id == PortId::transfer() {
        let mut prefixed_denom =
            base_trace.as_ref().parse().map_err(Error::TokenTransfer)?;
        if is_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &prefixed_denom,
        ) {
            let prefix =
                TracePrefix::new(src_port_id.clone(), src_channel_id.clone());
            prefixed_denom.remove_trace_prefix(&prefix);
        } else {
            let prefix =
                TracePrefix::new(dest_port_id.clone(), dest_channel_id.clone());
            prefixed_denom.add_trace_prefix(prefix);
        }
        return Ok(prefixed_denom.to_string());
    }

    if let Some((trace_path, base_class_id, token_id)) =
        trace::is_nft_trace(&base_trace)
    {
        let mut class_id = PrefixedClassId {
            trace_path,
            base_class_id: base_class_id.parse().map_err(Error::NftTransfer)?,
        };
        if is_nft_receiver_chain_source(
            src_port_id.clone(),
            src_channel_id.clone(),
            &class_id,
        ) {
            let prefix = NftTracePrefix::new(
                src_port_id.clone(),
                src_channel_id.clone(),
            );
            class_id.remove_trace_prefix(&prefix);
        } else {
            let prefix = NftTracePrefix::new(
                dest_port_id.clone(),
                dest_channel_id.clone(),
            );
            class_id.add_trace_prefix(prefix);
        }
        let token_id: TokenId = token_id.parse().map_err(Error::NftTransfer)?;
        return Ok(format!("{class_id}/{token_id}"));
    }

    Err(Error::Trace(format!(
        "Invalid IBC trace: {}",
        base_trace.as_ref()
    )))
}

/// Get the IbcToken from the source/destination ports and channels
pub fn received_ibc_token(
    ibc_denom: impl AsRef<str>,
    src_port_id: &PortId,
    src_channel_id: &ChannelId,
    dest_port_id: &PortId,
    dest_channel_id: &ChannelId,
) -> Result<Address, Error> {
    let ibc_trace = received_ibc_trace(
        ibc_denom,
        src_port_id,
        src_channel_id,
        dest_port_id,
        dest_channel_id,
    )?;
    trace::convert_to_address(ibc_trace)
        .map_err(|e| Error::Trace(format!("Invalid base token: {e}")))
}

/// Initialize storage in the genesis block.
pub fn init_genesis_storage<S>(storage: &mut S)
where
    S: State,
{
    // In ibc-go, u64 like a counter is encoded with big-endian:
    // https://github.com/cosmos/ibc-go/blob/89ffaafb5956a5ea606e1f1bf249c880bea802ed/modules/core/04-channel/keeper/keeper.go#L115

    let init_value = 0_u64;

    // the client counter
    let key = client_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial client counter");

    // the connection counter
    let key = connection_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial connection counter");

    // the channel counter
    let key = channel_counter_key();
    storage
        .write(&key, init_value)
        .expect("Unable to write the initial channel counter");
}

/// Update IBC-related data when finalizing block
pub fn finalize_block<D, H>(
    state: &mut WlState<D, H>,
    _events: &mut impl EmitEvents,
    is_new_epoch: bool,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    if is_new_epoch {
        clear_throughputs(state)?;
    }
    Ok(())
}

/// Clear the per-epoch throughputs (deposit and withdraw)
fn clear_throughputs<D, H>(
    state: &mut WlState<D, H>,
) -> Result<(), StorageError>
where
    D: 'static + DB + for<'iter> DBIter<'iter> + Sync,
    H: 'static + StorageHasher + Sync,
{
    for prefix in [deposit_prefix(), withdraw_prefix()] {
        let keys: Vec<Key> = state
            .iter_prefix(&prefix)?
            .map(|(key, _, _)| {
                Key::parse(key).expect("The key should be parsable")
            })
            .collect();
        for key in keys {
            state.write(&key, Amount::from(0))?;
        }
    }

    Ok(())
}

#[cfg(any(test, feature = "testing"))]
/// Testing helpers ans strategies for IBC
pub mod testing {
    use std::str::FromStr;

    use ibc::apps::transfer::types::msgs::transfer::MsgTransfer;
    use ibc::apps::transfer::types::packet::PacketData;
    use ibc::apps::transfer::types::{
        Amount, BaseDenom, Memo, PrefixedCoin, PrefixedDenom, TracePath,
        TracePrefix,
    };
    use ibc::core::channel::types::timeout::TimeoutHeight;
    use ibc::core::client::types::Height;
    use ibc::core::host::types::identifiers::{ChannelId, PortId};
    use ibc::core::primitives::Signer;
    use ibc::primitives::proto::Any;
    use ibc::primitives::{Timestamp, ToProto};
    use proptest::prelude::{Just, Strategy};
    use proptest::{collection, prop_compose, prop_oneof};

    prop_compose! {
        /// Generate an arbitrary port ID
        pub fn arb_ibc_port_id()(id in "[a-zA-Z0-9_+.\\-\\[\\]#<>]{2,128}") -> PortId {
            PortId::new(id).expect("generated invalid port ID")
        }
    }

    prop_compose! {
        /// Generate an arbitrary channel ID
        pub fn arb_ibc_channel_id()(id: u64) -> ChannelId {
            ChannelId::new(id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC height
        pub fn arb_ibc_height()(
            revision_number: u64,
            revision_height in 1u64..,
        ) -> Height {
            Height::new(revision_number, revision_height)
                .expect("generated invalid IBC height")
        }
    }

    /// Generate arbitrary timeout data
    pub fn arb_ibc_timeout_data() -> impl Strategy<Value = TimeoutHeight> {
        prop_oneof![
            arb_ibc_height().prop_map(TimeoutHeight::At),
            Just(TimeoutHeight::Never),
        ]
    }

    prop_compose! {
        /// Generate an arbitrary IBC timestamp
        pub fn arb_ibc_timestamp()(nanoseconds: u64) -> Timestamp {
            Timestamp::from_nanoseconds(nanoseconds).expect("generated invalid IBC timestamp")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_memo()(memo in "[a-zA-Z0-9_]*") -> Memo {
            memo.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC memo
        pub fn arb_ibc_signer()(signer in "[a-zA-Z0-9_]*") -> Signer {
            signer.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace prefix
        pub fn arb_ibc_trace_prefix()(
            port_id in arb_ibc_port_id(),
            channel_id in arb_ibc_channel_id(),
        ) -> TracePrefix {
            TracePrefix::new(port_id, channel_id)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC trace path
        pub fn arb_ibc_trace_path()(path in collection::vec(arb_ibc_trace_prefix(), 0..10)) -> TracePath {
            TracePath::from(path)
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC base denomination
        pub fn arb_ibc_base_denom()(base_denom in "[a-zA-Z0-9_]+") -> BaseDenom {
            BaseDenom::from_str(&base_denom).expect("generated invalid IBC base denomination")
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC prefixed denomination
        pub fn arb_ibc_prefixed_denom()(
            trace_path in arb_ibc_trace_path(),
            base_denom in arb_ibc_base_denom(),
        ) -> PrefixedDenom {
            PrefixedDenom {
                trace_path,
                base_denom,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC amount
        pub fn arb_ibc_amount()(value: [u64; 4]) -> Amount {
            value.into()
        }
    }

    prop_compose! {
        /// Generate an arbitrary prefixed coin
        pub fn arb_ibc_prefixed_coin()(
            denom in arb_ibc_prefixed_denom(),
            amount in arb_ibc_amount(),
        ) -> PrefixedCoin {
            PrefixedCoin {
                denom,
                amount,
            }
        }
    }

    prop_compose! {
        /// Generate arbitrary packet data
        pub fn arb_ibc_packet_data()(
            token in arb_ibc_prefixed_coin(),
            sender in arb_ibc_signer(),
            receiver in arb_ibc_signer(),
            memo in arb_ibc_memo(),
        ) -> PacketData {
            PacketData {
                token,
                sender,
                receiver,
                memo,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC transfer message
        pub fn arb_ibc_msg_transfer()(
            port_id_on_a in arb_ibc_port_id(),
            chan_id_on_a in arb_ibc_channel_id(),
            packet_data in arb_ibc_packet_data(),
            timeout_height_on_b in arb_ibc_timeout_data(),
            timeout_timestamp_on_b in arb_ibc_timestamp(),
        ) -> MsgTransfer {
            MsgTransfer {
                port_id_on_a,
                chan_id_on_a,
                packet_data,
                timeout_height_on_b,
                timeout_timestamp_on_b,
            }
        }
    }

    prop_compose! {
        /// Generate an arbitrary IBC any object
        pub fn arb_ibc_any()(msg_transfer in arb_ibc_msg_transfer()) -> Any {
            msg_transfer.to_any()
        }
    }
}
