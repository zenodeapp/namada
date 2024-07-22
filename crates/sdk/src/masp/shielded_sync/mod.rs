use masp_primitives::sapling::note_encryption::{
    try_sapling_note_decryption, PreparedIncomingViewingKey,
};
use masp_primitives::sapling::ViewingKey;
use masp_primitives::transaction::components::OutputDescription;
use masp_primitives::transaction::{Authorization, Authorized, Transaction};
use typed_builder::TypedBuilder;

use super::shielded_sync::utils::{MaspClient, RetryStrategy};
use crate::masp::shielded_sync::dispatcher::{AtomicFlag, Dispatcher};
use crate::masp::utils::DecryptedData;
use crate::masp::{ShieldedUtils, NETWORK};

pub mod dispatcher;
pub mod utils;

const DEFAULT_BUF_SIZE: usize = 32;
const DEFAULT_BATCH_SIZE: usize = 10;

/// A configuration used to tune the concurrency parameters of
/// the shielded sync and the client used to fetch data.
#[derive(TypedBuilder)]
pub struct ShieldedSyncConfig<M> {
    client: M,
    #[builder(default = RetryStrategy::Forever)]
    retry_strategy: RetryStrategy,
    #[builder(default = DEFAULT_BUF_SIZE)]
    channel_buffer_size: usize,
    #[builder(default = DEFAULT_BATCH_SIZE)]
    block_batch_size: usize,
}

impl<M> ShieldedSyncConfig<M>
where
    M: MaspClient,
{
    /// Retrieve the [`Dispatcher`] used to run shielded sync.
    pub async fn dispatcher<U, S>(
        self,
        spawner: S,
        utils: &U,
    ) -> Dispatcher<M, U, S>
    where
        U: ShieldedUtils,
    {
        dispatcher::new(
            spawner,
            self.client,
            utils,
            dispatcher::Config {
                retry_strategy: self.retry_strategy,
                block_batch_size: self.block_batch_size,
                channel_buffer_size: self.channel_buffer_size,
            },
        )
        .await
    }
}

/// Try to decrypt a MASP transaction with the provided key
pub fn trial_decrypt(
    shielded: Transaction,
    vk: ViewingKey,
    interrupt_flag: AtomicFlag,
) -> Vec<DecryptedData> {
    type Proof = OutputDescription<
        <
        <Authorized as Authorization>::SaplingAuth
        as masp_primitives::transaction::components::sapling::Authorization
        >::Proof
    >;

    let not_interrupted = || !interrupt_flag.get();

    shielded
        .sapling_bundle()
        .map_or(&vec![], |x| &x.shielded_outputs)
        .iter()
        .take_while(|_| not_interrupted())
        .filter_map(|so| {
            // Let's try to see if this viewing key can decrypt latest
            // note
            try_sapling_note_decryption::<_, Proof>(
                &NETWORK,
                1.into(),
                &PreparedIncomingViewingKey::new(&vk.ivk()),
                so,
            )
        })
        .collect()
}
