use crate::domain::BlobRef;

use super::super::BlobStoreError;

/// Immutable output storage owned by the composition root.  Runtime/tools
/// write a blob before returning its reference; the event stream only ever
/// receives the resulting content-addressed `BlobRef`.
pub trait BlobPort: Send + Sync {
    fn put(&self, bytes: &[u8], media_type: Option<&str>) -> Result<BlobRef, BlobStoreError>;
}

pub use BlobPort as BlobStore;
