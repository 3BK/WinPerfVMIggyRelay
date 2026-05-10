use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::Cryptography::{CertCloseStore, CertFreeCertificateContext, CERT_CONTEXT, HCERTSTORE},
};
use tokio::net::windows::named_pipe::NamedPipeServer;

/// Guard for Named Pipe connections (Prevents ERROR_PIPE_BUSY)
pub struct PipeGuard<'a>(pub &'a mut NamedPipeServer);
impl Drop for PipeGuard<'_> {
    fn drop(&mut self) { let _ = self.0.disconnect(); }
}

/// Guard for Windows Certificate Contexts
pub struct CertContextGuard(pub *const CERT_CONTEXT);
impl Drop for CertContextGuard {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { CertFreeCertificateContext(self.0) }; } }
}

/// Guard for Windows System Certificate Store
pub struct CertStoreGuard(pub HCERTSTORE);
impl Drop for CertStoreGuard {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { CertCloseStore(self.0, 0) }; } }
}
