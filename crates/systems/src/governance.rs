//! Governance abstract interfaces

pub use namada_storage::Result;

/// Abstract governance storage read interface
pub trait Read<S> {
    /// Check if an accepted proposal is being executed
    fn is_proposal_accepted(storage: &S, tx_data: &[u8]) -> Result<bool>;

    /// Get governance "max_proposal_period" parameter
    fn max_proposal_period(storage: &S) -> Result<u64>;
}
