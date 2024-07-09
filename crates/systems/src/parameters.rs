//! Parameters abstract interfaces

pub use namada_core::parameters::*;
use namada_core::storage;

/// Abstract parameters storage keys interface
pub trait Keys {
    /// Key for implicit VP
    fn implicit_vp_key() -> storage::Key;
}

/// Abstract parameters storage read interface
pub trait Read<S> {
    /// Storage error
    type Err;

    /// Read all parameters
    fn read(storage: &S) -> Result<Parameters, Self::Err>;

    /// Read MASP epoch multiplier
    fn masp_epoch_multiplier(storage: &S) -> Result<u64, Self::Err>;

    /// Read the the epoch duration parameter from store
    fn epoch_duration_parameter(
        storage: &S,
    ) -> Result<EpochDuration, Self::Err>;

    /// Helper function to retrieve the `is_native_token_transferable` protocol
    /// parameter from storage
    fn is_native_token_transferable(storage: &S) -> Result<bool, Self::Err>;
}

/// Abstract parameters storage write interface
pub trait Write<S>: Read<S> {
    /// Write all parameters
    fn write(storage: &mut S, parameters: &Parameters)
    -> Result<(), Self::Err>;
}
