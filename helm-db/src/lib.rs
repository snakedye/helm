mod fs;
mod indexer;

pub use fs::FileStore;
pub use indexer::RedbIndexer;

use helm_core::TryAsRef;

impl TryAsRef<FileStore> for () {
    fn try_as_ref(&self) -> Option<&FileStore> {
        None
    }
}
