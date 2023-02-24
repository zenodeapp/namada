//! Pfg

use super::token::Amount;
use super::Error;
use crate::ledger::pgf::{storage as pgf_storage, CounsilData};
use crate::ledger::storage_api::token::transfer as token_transfer;
use crate::ledger::storage_api::{self, StorageRead, StorageWrite};
use crate::types::address::Address;
use crate::types::token::{self, Transfer};
use crate::types::transaction::pgf::{InitCounsil, PgfReceipients};

/// A counsil creation transaction.
pub fn init_counsil<S>(
    storage: &mut S,
    data: InitCounsil,
) -> storage_api::Result<()>
where
    S: StorageRead + StorageWrite,
{
    let counsil_key =
        pgf_storage::get_candidate_key(&data.address, data.spending_cap);
    let counsil_data = CounsilData {
        epoch: data.epoch,
        data: data.data,
    };
    storage.write(&counsil_key, counsil_data)?;
    Ok(())
}

/// A pgf transaction to update the pgf receipients.
pub fn update_pgf_receipients<S>(
    storage: &mut S,
    data: PgfReceipients,
) -> storage_api::Result<Address>
where
    S: StorageRead + StorageWrite,
{
    let pgf_active_counsil = get_current_counsil_address(storage)?;
    let spent_amount = get_current_spent_amount(storage)?;
    let (counsil_address, _spent_amount) =
        match (pgf_active_counsil, spent_amount) {
            (Some(address), Some(amount)) => (address, amount),
            _ => {
                return Err(storage_api::Error::new_const(
                    "There is no active counsil",
                ));
            }
        };

    let project_key = pgf_storage::get_cpgf_recipient_key();
    storage.write(&project_key, data)?;

    Ok(counsil_address)
}

/// Check if the provided address is a validator address
pub fn get_current_counsil<S>(
    storage: &S,
) -> storage_api::Result<Option<(Address, Amount, Amount)>>
where
    S: StorageRead + StorageWrite,
{
    let counsil_key = pgf_storage::get_active_counsil_key();
    let counsil_address: Option<Address> = storage.read(&counsil_key)?;

    if let Some(counsil_address) = counsil_address {
        let spending_cap_key = pgf_storage::get_spending_cap_key();
        let spent_amount_key = pgf_storage::get_spent_amount_key();

        let spending_cap: Option<Amount> = storage.read(&spending_cap_key)?;
        let spent_amunt: Option<Amount> = storage.read(&spent_amount_key)?;

        match (spending_cap, spent_amunt) {
            (Some(spending_cap), Some(spent_amunt)) => {
                Ok(Some((counsil_address, spending_cap, spent_amunt)))
            }
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

/// Get the active counsil address
pub fn get_current_counsil_address<S>(
    storage: &S,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead + StorageWrite,
{
    let counsil_key = pgf_storage::get_active_counsil_key();
    storage.read(&counsil_key)
}

/// Get the current counsil spent amount
pub fn get_current_spent_amount<S>(
    storage: &S,
) -> storage_api::Result<Option<Amount>>
where
    S: StorageRead + StorageWrite,
{
    let counsil_key = pgf_storage::get_spent_amount_key();
    storage.read(&counsil_key)
}

/// Get all the valid and votable candidates
pub fn get_candidates<S>(
    storage: &S,
) -> storage_api::Result<Vec<(Address, Amount, String)>>
where
    S: StorageRead + StorageWrite,
{
    let current_epoch = storage.get_block_epoch()?;

    let candidates_expiration_key = pgf_storage::get_candidacy_expiration_key();
    let candidates_expiration: u64 = storage
        .read(&candidates_expiration_key)?
        .expect("Expiration key should be initialized.");
    let candidates_prefix_key = pgf_storage::candidates_prefix_key();

    let iter = storage_api::iter_prefix::<CounsilData>(
        storage,
        &candidates_prefix_key,
    )?;
    let candidates: Vec<(Address, Amount, String)> = iter
        .filter_map(|element| match element {
            Ok((key, counsil_data)) => {
                let candidate_address =
                    pgf_storage::get_candidate_address(&key);
                let candidate_spending_cap =
                    pgf_storage::get_candidate_spending_cap(&key);
                if counsil_data.epoch + candidates_expiration < current_epoch {
                    None
                } else {
                    match (candidate_address, candidate_spending_cap) {
                        (Some(address), Some(spending_cap)) => Some((
                            address.clone(),
                            spending_cap,
                            counsil_data.data,
                        )),
                        _ => None,
                    }
                }
            }
            Err(_) => None,
        })
        .collect();

    Ok(candidates)
}

/// Get the current receipients added by the counsil
pub fn get_receipients<S>(
    storage: &S,
) -> storage_api::Result<Option<PgfReceipients>>
where
    S: StorageRead + StorageWrite,
{
    let receipients = pgf_storage::get_cpgf_recipient_key();
    storage.read(&receipients)
}

/// Transfer some token from pgf address to an anddress
pub fn pgf_transfer<S>(
    storage: &mut S,
    transfer: Transfer,
) -> storage_api::Result<Option<Address>>
where
    S: StorageRead + StorageWrite,
{
    let pgf_active_counsil = get_current_counsil_address(storage)?;
    let spent_amount = get_current_spent_amount(storage)?;
    let (counsil_address, spent_amount) =
        match (pgf_active_counsil, spent_amount) {
            (Some(address), Some(amount)) => (address, amount),
            _ => {
                return Err(Error::SimpleMessage("There is no active counsil"));
            }
        };

    let token::Transfer {
        source,
        target,
        token,
        sub_prefix: _,
        amount,
        key: _,
        shielded: _,
    } = transfer;

    token_transfer(storage, &token, &source, &target, amount)?;

    let spent_amount_key = pgf_storage::get_spent_amount_key();
    storage.write(&spent_amount_key, spent_amount + amount)?;

    Ok(Some(counsil_address))
}
