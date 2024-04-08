//! A basic user VP supports both non-validator and validator accounts.
//!
//! This VP currently provides a signature verification against a public key for
//! sending tokens (receiving tokens is permissive).
//!
//! It allows to bond, unbond and withdraw tokens to and from PoS system with a
//! valid signature(s).
//!
//! For validator a tx to change a validator's commission rate or metadata
//! requires a valid signature(s) only from the validator.
//!
//! Any other storage key changes are allowed only with a valid signature.

use core::cell::RefCell;

use booleans::BoolResultUnitExt;
use namada_vp_prelude::*;
use proof_of_stake::parameters::MAX_VALIDATOR_METADATA_LEN;
use proof_of_stake::storage::{read_pos_params, validator_state_handle};
use proof_of_stake::storage_key::{
    self, is_below_capacity_validator_set_key, is_consensus_keys_key,
    is_consensus_validator_set_key, is_pos_key, is_total_consensus_stake_key,
    is_total_deltas_key, is_validator_address_raw_hash_key,
    is_validator_addresses_key, is_validator_commission_rate_key,
    is_validator_deltas_key, is_validator_eth_cold_key_key,
    is_validator_eth_hot_key_key, is_validator_max_commission_rate_change_key,
    is_validator_metadata_key, is_validator_set_positions_key,
    is_validator_state_epoched_meta_key, is_validator_state_key,
    is_validator_total_bond_or_unbond_key,
};

enum KeyType<'a> {
    TokenBalance { owner: &'a Address },
    TokenMinted,
    TokenMinter(&'a Address),
    PoS,
    Vp(&'a Address),
    Masp,
    PgfSteward(&'a Address),
    GovernanceVote(&'a Address),
    Ibc,
    Unknown,
}

impl<'a> From<&'a storage::Key> for KeyType<'a> {
    fn from(key: &'a storage::Key) -> KeyType<'a> {
        if let Some([_, owner]) =
            token::storage_key::is_any_token_balance_key(key)
        {
            Self::TokenBalance { owner }
        } else if token::storage_key::is_any_minted_balance_key(key).is_some() {
            Self::TokenMinted
        } else if let Some(minter) = token::storage_key::is_any_minter_key(key)
        {
            Self::TokenMinter(minter)
        } else if is_pos_key(key) {
            Self::PoS
        } else if gov_storage::keys::is_vote_key(key) {
            let voter_address = gov_storage::keys::get_voter_address(key);
            if let Some(address) = voter_address {
                Self::GovernanceVote(address)
            } else {
                Self::Unknown
            }
        } else if let Some(address) = pgf_storage::keys::is_stewards_key(key) {
            Self::PgfSteward(address)
        } else if let Some(address) = key.is_validity_predicate() {
            Self::Vp(address)
        } else if token::storage_key::is_masp_key(key) {
            Self::Masp
        } else if ibc::is_ibc_key(key) {
            Self::Ibc
        } else {
            Self::Unknown
        }
    }
}

#[validity_predicate]
fn validate_tx(
    ctx: &Ctx,
    tx_data: Tx,
    addr: Address,
    keys_changed: BTreeSet<storage::Key>,
    verifiers: BTreeSet<Address>,
) -> VpResult {
    debug_log!(
        "vp_user called with user addr: {}, key_changed: {:?}, verifiers: {:?}",
        addr,
        keys_changed,
        verifiers
    );

    let mut gadget = VerifySigGadget::new();

    keys_changed.iter().try_for_each(|key| {
        let key_type: KeyType = key.into();
        let mut validate_change = || match key_type {
            KeyType::TokenBalance { owner, .. } => {
                if owner == &addr {
                    let pre: token::Amount =
                        ctx.read_pre(key).into_vp_error()?.unwrap_or_default();
                    let post: token::Amount =
                        ctx.read_post(key).into_vp_error()?.unwrap_or_default();
                    let change = post.change() - pre.change();
                    gadget.verify_signatures_when(
                        // NB: debit has to signed, credit doesn't
                        || change.is_negative(),
                        ctx,
                        &tx_data,
                        &addr,
                    )?;
                    let sign = if change.non_negative() { "" } else { "-" };
                    debug_log!("token key: {key}, change: {sign}{change:?}");
                } else {
                    // If this is not the owner, allow any change
                    debug_log!(
                        "This address ({}) is not of owner ({}) of token key: \
                         {}",
                        addr,
                        owner,
                        key
                    );
                }
                Ok(())
            }
            KeyType::TokenMinted => {
                verifiers.contains(&address::MULTITOKEN).ok_or_else(|| {
                    VpError::Erased(
                        "The Multitoken VP should have been a verifier for \
                         this transaction, since a token was minted"
                            .into(),
                    )
                })
            }
            KeyType::TokenMinter(minter_addr) => gadget.verify_signatures_when(
                || minter_addr == &addr,
                ctx,
                &tx_data,
                &addr,
            ),
            KeyType::PoS => {
                validate_pos_changes(ctx, &tx_data, &addr, key, &mut gadget)
            }
            KeyType::PgfSteward(pgf_steward_addr) => gadget
                .verify_signatures_when(
                    || pgf_steward_addr == &addr,
                    ctx,
                    &tx_data,
                    &addr,
                ),
            KeyType::GovernanceVote(voter_addr) => gadget
                .verify_signatures_when(
                    || voter_addr == &addr,
                    ctx,
                    &tx_data,
                    &addr,
                ),
            KeyType::Vp(owner) => {
                let vp_overwritten: bool =
                    ctx.has_key_post(key).into_vp_error()?;
                gadget.verify_signatures_when(
                    || owner == &addr && vp_overwritten,
                    ctx,
                    &tx_data,
                    &addr,
                )
            }
            KeyType::Masp | KeyType::Ibc => Ok(()),
            KeyType::Unknown => {
                // Unknown changes require a valid signature
                gadget.verify_signatures(ctx, &tx_data, &addr)
            }
        };
        validate_change().inspect_err(|reason| {
            log_string(format!(
                "Modification on key {key} failed vp_user: {reason}"
            ));
        })
    })
}

fn validate_pos_changes(
    ctx: &Ctx,
    tx_data: &Tx,
    owner: &Address,
    key: &storage::Key,
    gadget: &mut VerifySigGadget,
) -> VpResult {
    // Kinda silly to wrap this in a ref cell, but it's required
    // for the mut borrow to be valid across all closures below
    let gadget = RefCell::new(gadget);

    // Bond or unbond
    let is_valid_bond_or_unbond_change = || {
        let bond_id = storage_key::is_bond_key(key)
            .map(|(bond_id, _)| bond_id)
            .or_else(|| storage_key::is_bond_epoched_meta_key(key))
            .or_else(|| {
                storage_key::is_unbond_key(key).map(|(bond_id, _, _)| bond_id)
            })
            .ok_or(VpError::Unspecified)?;
        gadget.borrow_mut().verify_signatures_when(
            // Bonds and unbonds changes for this address must be signed
            || &bond_id.source == owner,
            ctx,
            tx_data,
            owner,
        )
    };

    // Commission rate changes must be signed by the validator
    let is_valid_commission_rate_change = || {
        let validator = is_validator_commission_rate_key(key)
            .ok_or(VpError::Unspecified)?;

        (validator == owner).ok_or(VpError::Unspecified)?;

        gadget.borrow_mut().verify_signatures(ctx, tx_data, owner)
    };

    // Metadata changes must be signed by the validator whose
    // metadata is manipulated
    let is_valid_metadata_change = || {
        let is_valid = match is_validator_metadata_key(key) {
            Some(address) => {
                let metadata = ctx.post().read::<String>(key)?;
                let valid_len = if let Some(metadata) = metadata {
                    (metadata.len() as u64) <= MAX_VALIDATOR_METADATA_LEN
                } else {
                    true
                };
                if !valid_len {
                    return VpError::Erased(
                        "The metadata exceeds the maximum length".into(),
                    );
                }
                gadget.borrow_mut().verify_signatures_when(
                    address == owner,
                    ctx,
                    tx_data,
                    owner,
                )
            }
            None => VpError::Unspecified,
        };
        VpResult::Ok(is_valid)
    };

    // Changes in validator state
    let is_valid_state_change = || {
        let state_change = is_validator_state_key(key);
        let is_valid_state = match state_change {
            Some((address, epoch)) => {
                let params_pre = read_pos_params(&ctx.pre()).into_vp_error()?;
                let state_pre = validator_state_handle(address)
                    .get(&ctx.pre(), epoch, &params_pre)
                    .into_vp_error()?;

                let params_post =
                    read_pos_params(&ctx.post()).into_vp_error()?;
                let state_post = validator_state_handle(address)
                    .get(&ctx.post(), epoch, &params_post)
                    .into_vp_error()?;

                match (state_pre, state_post) {
                    (Some(pre), Some(post)) => {
                        use proof_of_stake::types::ValidatorState::*;

                        if (
                            // Deactivation case
                            matches!(
                                    pre,
                                    Consensus | BelowCapacity | BelowThreshold
                                ) && post == Inactive)
                            // Reactivation case
                            || (pre == Inactive && post != Inactive)
                            // Unjail case
                            || (pre == Jailed
                                && matches!(
                                    post,
                                    Consensus
                                        | BelowCapacity
                                        | BelowThreshold
                                ))
                        {
                            gadget.borrow_mut().verify_signatures_when(
                                || address == owner,
                                ctx,
                                tx_data,
                                owner,
                            )
                        } else if
                        // Bonding and unbonding may affect validator sets
                        matches!(
                            pre,
                            Consensus | BelowCapacity | BelowThreshold
                        ) && matches!(
                            post,
                            Consensus | BelowCapacity | BelowThreshold
                        ) {
                            Ok(())
                        } else {
                            // Unknown state changes are not allowed
                            Err(VpError::Unspecified)
                        }
                    }
                    (None, Some(_post)) => {
                        // Becoming a validator must be authorized
                        (address == owner).ok_or(VpError::Unspecified)?;
                        gadget
                            .borrow_mut()
                            .verify_signatures(ctx, tx_data, owner)
                    }
                    (Some(_pre), None) => {
                        // Clearing of old epoched data
                        Ok(())
                    }
                    _ => Err(VpError::Unspecified),
                }
            }
            None => Err(VpError::Unspecified),
        }
        .is_ok();

        (is_valid_state
            || is_validator_state_epoched_meta_key(key)
            || is_consensus_validator_set_key(key)
            || is_below_capacity_validator_set_key(key))
        .ok_or(VpError::Unspecified)
    };

    let is_valid_reward_claim = || {
        if let Some(bond_id) =
            storage_key::is_last_pos_reward_claim_epoch_key(key)
        {
            return gadget.borrow_mut().verify_signatures_when(
                // Claims for this address must be signed
                || &bond_id.source == owner,
                ctx,
                tx_data,
                owner,
            );
        }
        if let Some(bond_id) = storage_key::is_rewards_counter_key(key) {
            return gadget.borrow_mut().verify_signatures_when(
                // Redelegations auto-claim rewards
                || &bond_id.source == owner,
                ctx,
                tx_data,
                owner,
            );
        }

        Err(VpError::Unspecified)
    };

    let is_valid_redelegation = || {
        if storage_key::is_validator_redelegations_key(key) {
            return Ok(());
        }
        if let Some(delegator) =
            storage_key::is_delegator_redelegations_key(key)
        {
            return gadget.borrow_mut().verify_signatures_when(
                // Redelegations for this address must be signed
                || delegator == owner,
                ctx,
                tx_data,
                owner,
            );
        }
        if let Some(bond_id) = storage_key::is_rewards_counter_key(key) {
            return gadget.borrow_mut().verify_signatures_when(
                // Redelegations auto-claim rewards
                || &bond_id.source == owner,
                ctx,
                tx_data,
                owner,
            );
        }
        Err(VpError::Unspecified)
    };

    let is_valid_become_validator = || {
        let become_validator = is_validator_addresses_key(key)
            || is_consensus_keys_key(key)
            || is_validator_eth_cold_key_key(key).is_some()
            || is_validator_eth_hot_key_key(key).is_some()
            || is_validator_max_commission_rate_change_key(key).is_some()
            || is_validator_address_raw_hash_key(key).is_some();

        gadget.borrow_mut().verify_signatures_when(
            // A signature is required to become validator
            || become_validator,
            ctx,
            tx_data,
            owner,
        )
    };

    let pos_state_changes = is_valid_bond_or_unbond_change().is_ok()
        || is_total_deltas_key(key)
        || is_validator_deltas_key(key)
        || is_validator_total_bond_or_unbond_key(key)
        || is_validator_set_positions_key(key)
        || is_total_consensus_stake_key(key)
        || is_valid_state_change().is_ok()
        || is_valid_reward_claim().is_ok()
        || is_valid_redelegation().is_ok()
        || is_valid_commission_rate_change().is_ok()
        || is_valid_metadata_change().is_ok()
        || is_valid_become_validator().is_ok();
    let unknown_state_changes = !pos_state_changes;

    let result = gadget.borrow_mut().verify_signatures_when(
        || unknown_state_changes,
        ctx,
        tx_data,
        owner,
    );

    result.map_err(|err| match err {
        VpError::Unspecified => {
            VpError::Erased("Invalid PoS state changes".into())
        }
        err => err,
    })
}

#[cfg(test)]
mod tests {
    use std::panic;

    use address::testing::arb_non_internal_address;
    use namada::core::dec::Dec;
    use namada::core::storage::Epoch;
    use namada::ledger::pos::{GenesisValidator, PosParams};
    use namada::tx::data::{self, TxType};
    use namada::tx::{Authorization, Code, Data};
    use namada_test_utils::TestWasms;
    // Use this as `#[test]` annotation to enable logging
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::tx::{self, tx_host_env, TestTxEnv};
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::account::AccountPublicKeysMap;
    use namada_vp_prelude::key::RefTo;
    use proof_of_stake::jail_validator;
    use proptest::prelude::*;
    use storage::testing::arb_account_storage_key_no_vp;

    use super::*;

    /// Test that no-op transaction (i.e. no storage modifications) accepted.
    #[test]
    fn test_no_op_transaction() {
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let addr: Address = address::testing::established_address_1();
        let keys_changed: BTreeSet<storage::Key> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = BTreeSet::default();

        // The VP env must be initialized before calling `validate_tx`
        vp_host_env::init();

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).is_ok()
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );
        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                address,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a debit transfer without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_transfer_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );
        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a debit transfer with a valid signature is accepted.
    #[test]
    fn test_signed_debit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                address,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a non-validator PoS action that must be authorized is rejected
    /// without a valid signature.
    #[test]
    fn test_unsigned_non_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        // Initialize VP environment from non-validator PoS actions
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&vp_owner), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&vp_owner), &validator, unbond_amount)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test unjailing of a validator that causes a consensus validator to be
    /// demoted to the below-capacity set. Probing a bug as seen in the SE.
    #[test]
    fn test_unjail_with_demotion() {
        // Genesis validators
        let mut pos_params = PosParams::default();
        pos_params.owned.max_validator_slots = 2;

        // Common
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_1().ref_to();
        let eth_hot_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        // Unique
        let (validator1, validator2, validator3) = (
            address::testing::established_address_1(),
            address::testing::established_address_2(),
            address::testing::established_address_3(),
        );
        let (stake1, stake2, stake3) = (
            token::Amount::native_whole(1),
            token::Amount::native_whole(2),
            token::Amount::native_whole(3),
        );
        let (sk1, sk2, sk3) = (
            key::testing::keypair_2(),
            key::testing::keypair_3(),
            key::testing::keypair_4(),
        );
        let (ck1, ck2, ck3) = (sk1.ref_to(), sk2.ref_to(), sk3.ref_to());
        let genesis_validators = [
            GenesisValidator {
                address: validator1.clone(),
                tokens: stake1,
                consensus_key: ck1.clone(),
                protocol_key: protocol_key.clone(),
                commission_rate,
                max_commission_rate_change,
                eth_hot_key: eth_hot_key.clone(),
                eth_cold_key: eth_cold_key.clone(),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: validator3.clone(),
                tokens: stake3,
                consensus_key: ck3.clone(),
                protocol_key: protocol_key.clone(),
                commission_rate,
                max_commission_rate_change,
                eth_hot_key: eth_hot_key.clone(),
                eth_cold_key: eth_cold_key.clone(),
                metadata: Default::default(),
            },
            GenesisValidator {
                address: validator2.clone(),
                tokens: stake2,
                consensus_key: ck2.clone(),
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                eth_hot_key,
                eth_cold_key,
                metadata: Default::default(),
            },
        ];

        println!("\nValidator1: {}", &validator1);
        println!("Validator2: {}", &validator2);
        println!("Validator3: {}\n", &validator3);

        // Init PoS storage
        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();
        let token = address::testing::nam();

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Jail validator3
        jail_validator(
            &mut tx_env.state,
            &pos_params,
            &validator3,
            Epoch(0),
            Epoch(0),
        )
        .unwrap();

        // Initialize VP environment
        vp_host_env::init_from_tx(validator3.clone(), tx_env, |_address| {
            // Unjail validator3
            tx::ctx().unjail_validator(&validator3).unwrap()
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![ck3]);

        let mut vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        tx_data.set_code(Code::new(vec![], None));
        tx_data.add_section(Section::Authorization(Authorization::new(
            vec![tx_data.raw_header_hash()],
            pks_map.index_secret_keys(vec![sk3]),
            None,
        )));
        let signed_tx = tx_data.clone();
        vp_env.tx = signed_tx.clone();

        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        // dbg!(&keys_changed);
        // let verifiers: BTreeSet<Address> = BTreeSet::default();
        let verifiers: BTreeSet<Address> = vp_env.get_verifiers();
        dbg!(&verifiers);
        vp_host_env::set(vp_env);
        // for verifier in verifiers.clone() {
        // dbg!(&verifier);
        // assert!(
        //     validate_tx(
        //         &CTX,
        //         signed_tx.clone(),
        //         validator1,
        //         keys_changed.clone(),
        //         verifiers.clone()
        //     )
        //     .unwrap()
        // );
        assert!(
            validate_tx(
                &CTX,
                signed_tx.clone(),
                validator1,
                keys_changed.clone(),
                verifiers.clone()
            )
            .is_ok()
        );
    }

    /// Test that a PoS action to become validator that must be authorized is
    /// rejected without a valid signature.
    #[test]
    fn test_unsigned_become_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator,
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();

        // Spawn the accounts to be able to modify their storage
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);

        // Initialize VP environment from PoS action to become a validator
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            let consensus_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let protocol_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let commission_rate = Dec::new(5, 2).unwrap();
            let max_commission_rate_change = Dec::new(1, 2).unwrap();
            let args = data::pos::BecomeValidator {
                address: address.clone(),
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email: "cucumber@tastes.good".to_string(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
            };
            tx::ctx().become_validator(args).unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a validator PoS action that must be authorized is rejected
    /// without a valid signature.
    #[test]
    fn test_unsigned_validator_pos_action_rejected() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&validator, vec![public_key], 1);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the validator before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&validator, &token, amount);

        // Validator PoS actions
        vp_host_env::init_from_tx(validator.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&validator), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&validator), &validator, unbond_amount)
                .unwrap();
            tx::ctx().deactivate_validator(&validator).unwrap();
            tx::ctx()
                .change_validator_metadata(
                    &validator,
                    Some("email".to_owned()),
                    Some("desc".to_owned()),
                    Some("website".to_owned()),
                    Some("discord".to_owned()),
                    Some("avatar".to_owned()),
                    Some(Dec::new(6, 2).unwrap()),
                )
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(&CTX, tx_data, validator, keys_changed, verifiers)
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a non-validator PoS action that must be authorized is accepted
    /// with a valid signature.
    #[test]
    fn test_signed_non_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            eth_cold_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&vp_owner, &token, amount);

        // Initialize VP environment from non-validator PoS actions
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&vp_owner), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&vp_owner), &validator, unbond_amount)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a signed PoS action to become validator that must be
    /// authorized is accepted with a valid signature.
    #[test]
    fn test_signed_become_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let eth_cold_key = key::testing::keypair_3().ref_to();
        let eth_hot_key = key::testing::keypair_4().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator,
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key,
            eth_cold_key,
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = address::testing::established_address_2();

        // Spawn the accounts to be able to modify their storage
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from PoS action to become a validator
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            let consensus_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let protocol_key = key::common::PublicKey::Ed25519(
                key::testing::gen_keypair::<key::ed25519::SigScheme>().ref_to(),
            );
            let eth_cold_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let eth_hot_key =
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to();
            let commission_rate = Dec::new(5, 2).unwrap();
            let max_commission_rate_change = Dec::new(1, 2).unwrap();
            let args = data::pos::BecomeValidator {
                address: address.clone(),
                consensus_key,
                eth_cold_key,
                eth_hot_key,
                protocol_key,
                commission_rate,
                max_commission_rate_change,
                email: "cucumber@tastes.good".to_string(),
                description: None,
                website: None,
                discord_handle: None,
                avatar: None,
            };
            tx::ctx().become_validator(args).unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a validator PoS action that must be authorized is accepted
    /// with a valid signature.
    #[test]
    fn test_signed_validator_pos_action_accepted() {
        // Init PoS genesis
        let pos_params = PosParams::default();
        let validator = address::testing::established_address_3();
        let initial_stake = token::Amount::from_uint(10_098_123, 0).unwrap();
        let consensus_key = key::testing::keypair_2().ref_to();
        let protocol_key = key::testing::keypair_1().ref_to();
        let commission_rate = Dec::new(5, 2).unwrap();
        let max_commission_rate_change = Dec::new(1, 2).unwrap();

        let genesis_validators = [GenesisValidator {
            address: validator.clone(),
            tokens: initial_stake,
            consensus_key,
            protocol_key,
            commission_rate,
            max_commission_rate_change,
            eth_hot_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            eth_cold_key: key::common::PublicKey::Secp256k1(
                key::testing::gen_keypair::<key::secp256k1::SigScheme>()
                    .ref_to(),
            ),
            metadata: Default::default(),
        }];

        init_pos(&genesis_validators[..], &pos_params, Epoch(0));

        // Initialize a tx environment
        let mut tx_env = tx_host_env::take();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&validator, vec![public_key.clone()], 1);

        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&validator, &token, amount);

        // Validator PoS actions
        vp_host_env::init_from_tx(validator.clone(), tx_env, |_address| {
            // Bond the tokens, then unbond some of them
            tx::ctx()
                .bond_tokens(Some(&validator), &validator, bond_amount)
                .unwrap();
            tx::ctx()
                .unbond_tokens(Some(&validator), &validator, unbond_amount)
                .unwrap();
            tx::ctx().deactivate_validator(&validator).unwrap();
            tx::ctx()
                .change_validator_metadata(
                    &validator,
                    Some("email".to_owned()),
                    Some("desc".to_owned()),
                    Some("website".to_owned()),
                    Some("discord".to_owned()),
                    Some("avatar".to_owned()),
                    Some(Dec::new(6, 2).unwrap()),
                )
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![secret_key]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, validator, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a transfer on with accounts other than self is accepted.
    #[test]
    fn test_transfer_between_other_parties_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let source = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &target, &token]);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);

        let amount = token::DenominatedAmount::new(
            amount,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        );

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            tx::ctx().insert_verifier(address).unwrap();
            // Apply transfer in a transaction
            tx_host_env::token::transfer(
                tx::ctx(),
                &source,
                &target,
                &token,
                amount.amount(),
            )
            .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    prop_compose! {
        /// Generates an account address and a storage key inside its storage.
        fn arb_account_storage_subspace_key()
            // Generate an address
            (address in arb_non_internal_address())
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            (storage_key in arb_account_storage_key_no_vp(address.clone()),
            // Use the generated address too
            address in Just(address))
        -> (Address, Key) {
            (address, storage_key)
        }
    }

    proptest! {
        /// Test that an unsigned tx that performs arbitrary storage writes or
        /// deletes to  the account is rejected.
        #[test]
        fn test_unsigned_arb_storage_write_rejected(
            (vp_owner, storage_key) in arb_account_storage_subspace_key(),
            // Generate bytes to write. If `None`, delete from the key instead
            storage_value in any::<Option<Vec<u8>>>(),
        ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            // Initialize VP environment from a transaction
            vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                // Write or delete some data in the transaction
                if let Some(value) = &storage_value {
                    tx::ctx().write(&storage_key, value).unwrap();
                } else {
                    tx::ctx().delete(&storage_key).unwrap();
                }
            });

            let vp_env = vp_host_env::take();
            let mut tx_data = Tx::from_type(TxType::Raw);
            tx_data.set_data(Data::new(vec![]));
            let keys_changed: BTreeSet<storage::Key> =
                vp_env.all_touched_storage_keys();
            let verifiers: BTreeSet<Address> = BTreeSet::default();
            vp_host_env::set(vp_env);
            assert!(
                panic::catch_unwind(|| {
                    validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
                })
                .err()
                .map(|a| a.downcast_ref::<String>().cloned().unwrap())
                .unwrap()
                .contains("InvalidSectionSignature")
            );
        }
    }

    proptest! {
            /// Test that a signed tx that performs arbitrary storage writes or
            /// deletes to the account is accepted.
            #[test]
            fn test_signed_arb_storage_write(
                (vp_owner, storage_key) in arb_account_storage_subspace_key(),
                // Generate bytes to write. If `None`, delete from the key instead
                storage_value in any::<Option<Vec<u8>>>(),
            ) {
                // Initialize a tx environment
                let mut tx_env = TestTxEnv::default();

                let keypair = key::testing::keypair_1();
                let public_key = keypair.ref_to();

                // Spawn all the accounts in the storage key to be able to modify
                // their storage
                let storage_key_addresses = storage_key.find_addresses();
                tx_env.spawn_accounts(storage_key_addresses);
                tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

                // Initialize VP environment from a transaction
                vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |_address| {
                    // Write or delete some data in the transaction
                    if let Some(value) = &storage_value {
                        tx::ctx().write(&storage_key, value).unwrap();
                    } else {
                        tx::ctx().delete(&storage_key).unwrap();
                    }
                });

                let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

                let mut vp_env = vp_host_env::take();
                let mut tx = vp_env.tx.clone();
                tx.set_code(Code::new(vec![], None));
                tx.set_data(Data::new(vec![]));
                tx.add_section(Section::Authorization(Authorization::new(
    vec![                tx.raw_header_hash()],
                    pks_map.index_secret_keys(vec![keypair]),
                    None,
                )));
                let signed_tx = tx.clone();
                vp_env.tx = signed_tx.clone();
                let keys_changed: BTreeSet<storage::Key> =
                vp_env.all_touched_storage_keys();
                let verifiers: BTreeSet<Address> = BTreeSet::default();
                vp_host_env::set(vp_env);
                assert!(validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers).is_ok());
            }
        }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        tx_data.set_code(Code::new(vec![], None));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            panic::catch_unwind(|| {
                validate_tx(&CTX, tx_data, vp_owner, keys_changed, verifiers)
            })
            .err()
            .map(|a| a.downcast_ref::<String>().cloned().unwrap())
            .unwrap()
            .contains("InvalidSectionSignature")
        );
    }

    /// Test that a validity predicate update with a valid signature is
    /// accepted.
    #[test]
    fn test_signed_vp_update_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();
        tx_env.init_parameters(None, None, None, None);

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }

    /// Test that a validity predicate update is accepted if allowed
    #[test]
    fn test_signed_vp_update_allowed_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let vp_owner = address::testing::established_address_1();
        let keypair = key::testing::keypair_1();
        let public_key = keypair.ref_to();
        let vp_code = TestWasms::VpAlwaysTrue.read_bytes();
        let vp_hash = sha256(&vp_code);
        // for the update
        tx_env.store_wasm_code(vp_code);

        tx_env.init_parameters(
            None,
            Some(vec![vp_hash.to_string()]),
            None,
            None,
        );

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner]);
        tx_env.init_account_storage(&vp_owner, vec![public_key.clone()], 1);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(vp_owner.clone(), tx_env, |address| {
            // Update VP in a transaction
            tx::ctx()
                .update_validity_predicate(address, vp_hash, &None)
                .unwrap();
        });

        let pks_map = AccountPublicKeysMap::from_iter(vec![public_key]);

        let mut vp_env = vp_host_env::take();
        let mut tx = vp_env.tx.clone();
        tx.set_data(Data::new(vec![]));
        tx.set_code(Code::new(vec![], None));
        tx.add_section(Section::Authorization(Authorization::new(
            vec![tx.raw_header_hash()],
            pks_map.index_secret_keys(vec![keypair]),
            None,
        )));
        let signed_tx = tx.clone();
        vp_env.tx = signed_tx.clone();
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);
        assert!(
            validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers)
                .is_ok()
        );
    }
}
