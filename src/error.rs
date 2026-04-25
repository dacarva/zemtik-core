/// Top-level error type for the zemtik public API.
///
/// Returned by [`build_proxy_router`] and [`run_proxy`]. Wraps the underlying
/// anyhow error so callers get a typed boundary without a direct anyhow dependency.
///
/// [`build_proxy_router`]: crate::proxy::build_proxy_router
/// [`run_proxy`]: crate::proxy::run_proxy
#[derive(Debug)]
pub struct ZemtikError(pub(crate) anyhow::Error);

impl std::fmt::Display for ZemtikError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for ZemtikError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<anyhow::Error> for ZemtikError {
    fn from(e: anyhow::Error) -> Self {
        ZemtikError(e)
    }
}
