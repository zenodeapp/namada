
use typed_builder::TypedBuilder;
use crate::masp::ShieldedUtils;
use crate::masp::shielded_sync::dispatcher::Dispatcher;
use crate::task_env::{TaskEnvironment, TaskSpawner};
use super::shielded_sync::utils::{MaspClient, RetryStrategy};

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
        utils: &U
    ) -> Dispatcher<M, U, S>
    where
        U: ShieldedUtils
    {
        dispatcher::new(
            spawner,
            self.client,
            utils,
            dispatcher::Config {
                block_batch_size: self.block_batch_size,
                channel_buffer_size: self.channel_buffer_size,
            }
        ).await
    }
}

