//! Implicit account VP. All implicit accounts share this same VP.
//!
//! This VP currently provides a signature verification against a public key for
//! sending tokens (receiving tokens is permissive).
//!
//! It allows to reveal a PK, as long as its address matches with the address
//! that can be derived from the PK.
//!
//! It allows to bond, unbond and withdraw tokens to and from PoS system with a
//! valid signature.
//!
//! Any other storage key changes are allowed only with a valid signature.

use core::cell::RefCell;

use booleans::BoolResultUnitExt;
use namada_vp_prelude::*;

enum KeyType<'a> {
    /// Public key - written once revealed
    Pk(&'a Address),
    TokenBalance {
        owner: &'a Address,
    },
    TokenMinted,
    TokenMinter(&'a Address),
    PoS,
    Masp,
    PgfSteward(&'a Address),
    GovernanceVote(&'a Address),
    Ibc,
    Unknown,
}

impl<'a> From<&'a storage::Key> for KeyType<'a> {
    fn from(key: &'a storage::Key) -> KeyType<'a> {
        if let Some(address) = account::is_pks_key(key) {
            Self::Pk(address)
        } else if let Some([_, owner]) =
            token::storage_key::is_any_token_balance_key(key)
        {
            Self::TokenBalance { owner }
        } else if token::storage_key::is_any_minted_balance_key(key).is_some() {
            Self::TokenMinted
        } else if let Some(minter) = token::storage_key::is_any_minter_key(key)
        {
            Self::TokenMinter(minter)
        } else if proof_of_stake::storage_key::is_pos_key(key) {
            Self::PoS
        } else if let Some(address) = pgf_storage::keys::is_stewards_key(key) {
            Self::PgfSteward(address)
        } else if gov_storage::keys::is_vote_key(key) {
            let voter_address = gov_storage::keys::get_voter_address(key);
            if let Some(address) = voter_address {
                Self::GovernanceVote(address)
            } else {
                Self::Unknown
            }
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
            KeyType::Pk(owner) => {
                if owner == &addr {
                    let key_was_not_already_revealed =
                        !ctx.has_key_pre(key).into_vp_error()?;
                    key_was_not_already_revealed.ok_or_else(|| {
                        VpError::Erased(format!(
                            "Public key of {addr} has already been revealed"
                        ))
                    })?;

                    let pubkey_in_storage =
                        ctx.read_post(key).into_vp_error()?;
                    pubkey_in_storage.map_or_else(
                        || {
                            Err(VpError::Erased(
                                "Public keys that have been revealed cannot \
                                 be deleted"
                                    .into(),
                            ))
                        },
                        |pk: key::common::PublicKey| {
                            let addr_from_pk: Address = (&pk).into();
                            let pk_derived_addr_is_correct =
                                addr_from_pk == addr;

                            // Check that address matches with the address
                            // derived from the PK
                            pk_derived_addr_is_correct.ok_or_else(|| {
                                VpError::Erased(format!(
                                    "The address derived from the revealed \
                                     public key {addr_from_pk} does not match \
                                     the implicit account's address {addr}"
                                ))
                            })
                        },
                    )?;
                }
                Ok(())
            }
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
            KeyType::Masp | KeyType::Ibc => Ok(()),
            KeyType::Unknown => {
                // Unknown changes require a valid signature
                gadget.verify_signatures(ctx, &tx_data, &addr)
            }
        };
        validate_change().inspect_err(|reason| {
            log_string(format!(
                "Modification on key {key} failed vp_implicit: {reason}"
            ));
        })
    })
}

// TODO: handle I/O errors
// TODO: pass back to user proper PoS err reporting
fn validate_pos_changes(
    ctx: &Ctx,
    tx_data: &Tx,
    owner: &Address,
    key: &storage::Key,
    gadget: &mut VerifySigGadget,
) -> VpResult {
    use proof_of_stake::{storage, storage_key};

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

    // Changes in validator state
    let is_valid_state_change = || {
        let state_change = storage_key::is_validator_state_key(key);
        let is_valid_state = match state_change {
            Some((address, epoch)) => {
                let params_pre =
                    storage::read_pos_params(&ctx.pre()).into_vp_error()?;
                let state_pre = storage::validator_state_handle(address)
                    .get(&ctx.pre(), epoch, &params_pre)
                    .into_vp_error()?;

                let params_post =
                    storage::read_pos_params(&ctx.post()).into_vp_error()?;
                let state_post = storage::validator_state_handle(address)
                    .get(&ctx.post(), epoch, &params_post)
                    .into_vp_error()?;

                match (state_pre, state_post) {
                    (Some(pre), Some(post)) => {
                        use proof_of_stake::types::ValidatorState::*;

                        // Bonding and unbonding may affect validator sets
                        if matches!(
                            pre,
                            Consensus | BelowCapacity | BelowThreshold
                        ) && matches!(
                            post,
                            Consensus | BelowCapacity | BelowThreshold
                        ) {
                            true
                        } else {
                            // Unknown state changes are not allowed
                            false
                        }
                    }
                    (Some(_pre), None) => {
                        // Clearing of old epoched data
                        true
                    }
                    _ => false,
                }
            }
            None => false,
        };

        (is_valid_state
            || storage_key::is_validator_state_epoched_meta_key(key)
            || storage_key::is_consensus_validator_set_key(key)
            || storage_key::is_below_capacity_validator_set_key(key))
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

    let pos_state_changes = is_valid_bond_or_unbond_change().is_ok()
        || storage_key::is_total_deltas_key(key)
        || storage_key::is_validator_deltas_key(key)
        || storage_key::is_validator_total_bond_or_unbond_key(key)
        || storage_key::is_validator_set_positions_key(key)
        || storage_key::is_total_consensus_stake_key(key)
        || is_valid_state_change().is_ok()
        || is_valid_reward_claim().is_ok()
        || is_valid_redelegation().is_ok();
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

    // Use this as `#[test]` annotation to enable logging
    use namada::core::dec::Dec;
    use namada::core::storage::Epoch;
    use namada::ledger::pos::{GenesisValidator, PosParams};
    use namada::tx::data::TxType;
    use namada::tx::{Authorization, Code, Data};
    use namada_test_utils::TestWasms;
    use namada_tests::log::test;
    use namada_tests::native_vp::pos::init_pos;
    use namada_tests::tx::{self, tx_host_env, TestTxEnv};
    use namada_tests::vp::vp_host_env::storage::Key;
    use namada_tests::vp::*;
    use namada_tx_prelude::{StorageWrite, TxEnv};
    use namada_vp_prelude::account::AccountPublicKeysMap;
    use namada_vp_prelude::key::RefTo;
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

    /// Test that a PK can be revealed when it's not revealed and cannot be
    /// revealed anymore once it's already revealed.
    #[test]
    fn test_can_reveal_pk() {
        // The SK to be used for the implicit account
        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let addr: Address = (&public_key).into();

        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();
        tx_env.init_parameters(None, None, None, None);

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Apply reveal_pk in a transaction
            tx_host_env::key::reveal_pk(tx::ctx(), &public_key).unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            validate_tx(&CTX, tx_data, addr.clone(), keys_changed, verifiers)
                .is_ok(),
            "Revealing PK that's not yet revealed and is matching the address \
             must be accepted"
        );

        // Commit the transaction and create another tx_env
        let vp_env = vp_host_env::take();
        tx_host_env::set_from_vp_env(vp_env);
        tx_host_env::commit_tx_and_block();
        let tx_env = tx_host_env::take();

        // Try to reveal it again
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Apply reveal_pk in a transaction
            tx_host_env::key::reveal_pk(tx::ctx(), &public_key).unwrap();
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).is_err(),
            "Revealing PK that's already revealed should be rejected"
        );
    }

    /// Test that a revealed PK that doesn't correspond to the account's address
    /// is rejected.
    #[test]
    fn test_reveal_wrong_pk_rejected() {
        // The SK to be used for the implicit account
        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let addr: Address = (&public_key).into();

        // Another SK to be revealed for the address above (not matching it)
        let mismatched_sk = key::testing::keypair_2();
        let mismatched_pk = mismatched_sk.ref_to();

        // Initialize a tx environment
        let tx_env = TestTxEnv::default();

        // Initialize VP environment from a transaction
        vp_host_env::init_from_tx(addr.clone(), tx_env, |_address| {
            // Do the same as reveal_pk, but with the wrong key
            let _ = account::set_public_key_at(
                tx_host_env::ctx(),
                &addr,
                &mismatched_pk,
                0,
            );
        });

        let vp_env = vp_host_env::take();
        let mut tx_data = Tx::from_type(TxType::Raw);
        tx_data.set_data(Data::new(vec![]));
        let keys_changed: BTreeSet<storage::Key> =
            vp_env.all_touched_storage_keys();
        let verifiers: BTreeSet<Address> = BTreeSet::default();
        vp_host_env::set(vp_env);

        assert!(
            validate_tx(&CTX, tx_data, addr, keys_changed, verifiers).is_err(),
            "Mismatching PK must be rejected"
        );
    }

    /// Test that a credit transfer is accepted.
    #[test]
    fn test_credit_transfer_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let source = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &token]);
        // write the denomination of NAM into storage
        token::write_denom(
            &mut tx_env.state,
            &token,
            token::NATIVE_MAX_DECIMAL_PLACES.into(),
        )
        .unwrap();

        // Credit the tokens to the source before running the transaction to be
        // able to transfer from it
        tx_env.credit_tokens(&source, &token, amount);

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

    /// Test that a PoS action that must be authorized is rejected without a
    /// valid signature.
    #[test]
    fn test_unsigned_pos_action_rejected() {
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

        tx_env.init_parameters(None, Some(vec![]), Some(vec![]), None);

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);

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

        // Initialize VP environment from a transaction
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

    /// Test that a PoS action that must be authorized is accepted with a
    /// valid signature.
    #[test]
    fn test_signed_pos_action_accepted() {
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
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();
        let bond_amount = token::Amount::from_uint(5_098_123, 0).unwrap();
        let unbond_amount = token::Amount::from_uint(3_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&target, &token]);
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

        // Initialize VP environment from a transaction
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

    /// Test that a debit transfer without a valid signature is rejected.
    #[test]
    fn test_unsigned_debit_transfer_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);

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

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let target = address::testing::established_address_2();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        tx_env.init_parameters(None, None, None, None);

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

    /// Test that a transfer on with accounts other than self is accepted.
    #[test]
    fn test_transfer_between_other_parties_accepted() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
        let source = address::testing::established_address_2();
        let target = address::testing::established_address_3();
        let token = address::testing::nam();
        let amount = token::Amount::from_uint(10_098_123, 0).unwrap();

        // Spawn the accounts to be able to modify their storage
        tx_env.spawn_accounts([&vp_owner, &source, &target, &token]);
        tx_env.init_account_storage(&vp_owner, vec![public_key], 1);

        // Credit the tokens to the VP owner before running the transaction to
        // be able to transfer from it
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

    /// Generates a keypair, derive an implicit address from it and generate
    /// a storage key inside its storage.
    fn arb_account_storage_subspace_key()
    -> impl Strategy<Value = (key::common::SecretKey, Address, Key)> {
        // Generate a keypair
        key::testing::arb_common_keypair().prop_flat_map(|sk| {
            let pk = sk.ref_to();
            let addr: Address = (&pk).into();
            // Generate a storage key other than its VP key (VP cannot be
            // modified directly via `write`, it has to be modified via
            // `tx::update_validity_predicate`.
            let storage_key = arb_account_storage_key_no_vp(addr.clone());
            (Just(sk), Just(addr), storage_key)
        })
    }

    proptest! {
        /// Test that an unsigned tx that performs arbitrary storage writes
    /// or deletes to  the account is rejected.
        #[test]
        fn test_unsigned_arb_storage_write_rejected(
            (_sk, vp_owner, storage_key) in arb_account_storage_subspace_key(),
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

    fn test_signed_arb_storage_write(
        (secret_key, vp_owner, storage_key) in arb_account_storage_subspace_key(),
        // Generate bytes to write. If `None`, delete from the key instead
        storage_value in any::<Option<Vec<u8>>>(),
    ) {
            // Initialize a tx environment
            let mut tx_env = TestTxEnv::default();

            // Spawn all the accounts in the storage key to be able to modify
            // their storage
            let storage_key_addresses = storage_key.find_addresses();
            tx_env.spawn_accounts(storage_key_addresses);

            let public_key = secret_key.ref_to();
            let _ = account::set_public_key_at(tx_host_env::ctx(), &vp_owner, &public_key, 0);

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
            assert!(validate_tx(&CTX, signed_tx, vp_owner, keys_changed, verifiers).is_ok());
        }
    }

    /// Test that a validity predicate update without a valid signature is
    /// rejected.
    #[test]
    fn test_unsigned_vp_update_rejected() {
        // Initialize a tx environment
        let mut tx_env = TestTxEnv::default();

        let secret_key = key::testing::keypair_1();
        let public_key = secret_key.ref_to();
        let vp_owner: Address = (&public_key).into();
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
