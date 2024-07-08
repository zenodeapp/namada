//! The storage prefix iterators can be used to iterate over a common prefix of
//! storage keys.

use namada_core::collections::HashMap;
use namada_state::PrefixIter;

/// A temporary iterators storage, used during a wasm run after which it's
/// dropped. Each iterator is assigned a [`PrefixIteratorId`].
#[derive(Debug)]
pub struct PrefixIterators<'iter, DB>
where
    DB: namada_state::DB + namada_state::DBIter<'iter>,
{
    index: PrefixIteratorId,
    iterators: HashMap<PrefixIteratorId, PrefixIter<'iter, DB>>,
}

impl<'iter, DB> PrefixIterators<'iter, DB>
where
    DB: namada_state::DB + namada_state::DBIter<'iter>,
{
    /// Insert a new prefix iterator to the temporary storage. Returns `None` on
    /// prefix iterator ID overflow
    pub fn insert(
        &mut self,
        iter: PrefixIter<'iter, DB>,
    ) -> Option<PrefixIteratorId> {
        let id = self.index;
        self.iterators.insert(id, iter);
        self.index = id.next_id()?;
        Some(id)
    }

    /// Get the next item in the given prefix iterator.
    pub fn next(
        &mut self,
        id: PrefixIteratorId,
    ) -> Option<<PrefixIter<'iter, DB> as Iterator>::Item> {
        self.iterators.get_mut(&id).and_then(|i| i.next())
    }

    /// Get prefix iterator with the given ID.
    pub fn get_mut(
        &mut self,
        id: PrefixIteratorId,
    ) -> Option<&mut PrefixIter<'iter, DB>> {
        self.iterators.get_mut(&id)
    }
}

impl<'iter, DB> Default for PrefixIterators<'iter, DB>
where
    DB: namada_state::DB + namada_state::DBIter<'iter>,
{
    fn default() -> Self {
        Self {
            index: PrefixIteratorId::default(),
            iterators: HashMap::default(),
        }
    }
}

/// A prefix iterator identifier for the temporary storage [`PrefixIterators`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct PrefixIteratorId(u64);

impl PrefixIteratorId {
    /// Initialize a new ID.
    pub fn new(id: u64) -> Self {
        PrefixIteratorId(id)
    }

    /// Get the ID as `u64`.
    pub fn id(&self) -> u64 {
        self.0
    }

    /// Get the ID for the next prefix iterator. Returns `None` on overflow
    fn next_id(&self) -> Option<PrefixIteratorId> {
        Some(PrefixIteratorId(self.0.checked_add(1)?))
    }
}
