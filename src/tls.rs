use crate::audit::AuditGuard;
use crate::guards::{CertContextGuard, CertStoreGuard};

use log::Level;
use rustls::{ClientConfig, RootCertStore};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Security::Cryptography::*;

/// Minimal representation of Windows CRYPT_DATA_BLOB / CRYPT_HASH_BLOB.
/// Windows APIs often typedef these; windows-sys does not always expose every alias. 【1-5ca74a】
#[repr(C)]
struct CRYPT_DATA_BLOB_REPR {
    cbData: u32,
    pbData: *mut u8,
}

/// Build rustls ClientConfig.
///
/// Parameters:
/// - client_cert_sha1: SHA1 thumbprint hex for cert lookup in LocalMachine\MY (supports ":" or no ":").
/// - server_cert_sha256_pin: kept for configuration completeness (pin enforcement requires custom verifier).
/// - audit: AuditGuard for logging.
///
/// Notes:
/// - Uses rustls builder API: with_root_certificates + with_no_client_auth. 【2-14f265】【1-5ca74a】
/// - We sanity-check that the certificate exists and log expiry warnings.
/// - mTLS client authentication (private key via CNG/CryptoAPI) is TODO; this config does NOT present a client certificate.
pub fn build_rustls_config(
    client_cert_sha1: &str,
    server_cert_sha256_pin: &str,
    audit: &AuditGuard,
) -> Arc<ClientConfig> {
    // Root store
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Validate cert presence and log expiry warning if possible.
    match find_cert_by_sha1_thumbprint(client_cert_sha1) {
        Ok(cert_info) => {
            if let Some(days) = cert_info.days_until_expiry() {
                if days < 30 {
                    audit.log(
                        Level::Warn,
                        1043,
                        &format!("Client certificate expiry approaching; days_remaining={days}"),
                    );
                }
            }
        }
        Err(e) => {
            audit.log(Level::Error, 1042, &format!("Client certificate lookup failed: {e}"));
        }
    }

    // Server pin is not enforced here. Enforcing pinning requires a custom certificate verifier.
    // We keep it so config remains aligned with the spec.
    let _ = server_cert_sha256_pin;

    // rustls 0.23: use with_root_certificates (not with_root_store). 【2-14f265】【1-5ca74a】
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls provider/version configuration error")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(cfg)
}

/// Small wrapper for cert expiry metadata.
struct CertMeta {
    not_after_filetime: FILETIME,
}

impl CertMeta {
    /// Returns days until expiry (rounded down), or None if conversion fails.
    fn days_until_expiry(&self) -> Option<i64> {
        let expiry_unix = filetime_to_unix_time(self.not_after_filetime)?;
        let now = SystemTime::now();
        if expiry_unix <= now {
            return Some(0);
        }
        let diff = expiry_unix.duration_since(now).ok()?;
        Some((diff.as_secs() / 86_400) as i64)
    }
}

/// Find certificate in LocalMachine\MY by SHA1 thumbprint.
/// Returns metadata including NotAfter FILETIME.
fn find_cert_by_sha1_thumbprint(sha1_hex: &str) -> Result<CertMeta, String> {
    let sha1 = hex::decode(sha1_hex.replace(":", ""))
        .map_err(|e| format!("Invalid SHA1 thumbprint hex: {e}"))?;

    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM as *const u8,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            widestring::WideCString::from_str("MY")
                .map_err(|e| format!("WideCString error: {e}"))?
                .as_ptr() as *const _,
        );

        if store.is_null() {
            return Err("CertOpenStore(LocalMachine\\MY) failed".into());
        }
        let _sg = CertStoreGuard(store);

        let mut blob = CRYPT_DATA_BLOB_REPR {
            cbData: sha1.len() as u32,
            pbData: sha1.as_ptr() as *mut u8,
        };

        let ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            (&mut blob as *mut CRYPT_DATA_BLOB_REPR) as *const _,
            std::ptr::null(),
        );

        if ctx.is_null() {
            return Err("Certificate not found by SHA1 thumbprint".into());
        }
        let _cg = CertContextGuard(ctx);

        // pCertInfo is a raw pointer; must dereference it to access fields. 【1-5ca74a】
        let cert_info = (*ctx).pCertInfo;
        if cert_info.is_null() {
            return Err("CERT_CONTEXT.pCertInfo was null".into());
        }

        let not_after = (*cert_info).NotAfter;

        Ok(CertMeta {
            not_after_filetime: not_after,
        })
    }
}

/// Convert Windows FILETIME to SystemTime (UTC).
///
/// FILETIME is the number of 100-nanosecond intervals since 1601-01-01.
/// Unix epoch is 1970-01-01.
/// Difference between epochs: 11644473600 seconds.
fn filetime_to_unix_time(ft: FILETIME) -> Option<SystemTime> {
    let low = ft.dwLowDateTime as u64;
    let high = ft.dwHighDateTime as u64;
    let ticks_100ns = (high << 32) | low;

    // Convert to seconds/nanos
    let total_nanos = ticks_100ns.checked_mul(100)?; // 100ns units -> ns
    let total_secs = total_nanos / 1_000_000_000;
    let rem_nanos = (total_nanos % 1_000_000_000) as u32;

    // Convert to Unix epoch
    const EPOCH_DIFF_SECS: u64 = 11_644_473_600;

    if total_secs < EPOCH_DIFF_SECS {
        // Before Unix epoch
        return Some(UNIX_EPOCH);
    }

    let unix_secs = total_secs - EPOCH_DIFF_SECS;
    Some(UNIX_EPOCH + Duration::new(unix_secs, rem_nanos))
}
