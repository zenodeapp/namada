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

    // Listen for notes sent to our viewing keys, only if we are syncing
    // (i.e. in a confirmed status)
    shielded.
        sapling_bundle()
        .map_or(&vec![], |x| &x.shielded_outputs)
        .iter()
        .filter_map(|so| {
                if interrupt_flag.get() {
                    return None;
                }
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
