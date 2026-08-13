use std::{future::Future, pin::Pin};

use super::super::model::{ModelOutcome, ModelRequest};
use super::super::ModelError;

pub trait ModelPort: Send + Sync {
    fn complete<'a>(
        &'a self,
        request: &'a ModelRequest,
    ) -> Pin<Box<dyn Future<Output = Result<ModelOutcome, ModelError>> + Send + 'a>>;
}

pub use ModelPort as ModelExecutor;
