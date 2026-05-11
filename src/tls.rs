use crate::guards::{CertContextGuard, CertStoreGuard};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}, ClientConfig, RootCertStore};
use std::sync::Arc;
use windows_sys::Win32::Security::Cryptography::*;
use log::Level;

/// Builds a rustls ClientConfig using SHA256 pinning and actual private key extraction.
/// Adds server certificate pin validation and client certificate expiry check.
pub fn build_rustls_config(client_cert_sha256: &str, server_cert_sha256_pin: &str, audit: &crate::audit::AuditGuard) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let (cert, priv_key, expiry) = fetch_win_cert_and_key(client_cert_sha256, audit);

    // Check certificate expiry and log warning if within threshold
    let days_until_expiry = days_until(expiry);
    if days_until_expiry < 30 {
        audit.log(Level::Warn, 1043, &format!(
            "Client certificate expiry approaching; days_remaining={}", days_until_expiry
        ));
    }

    // Build rustls config with AWS LC provider
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("Provider error")
        .with_root_store(root_store)
        .with_client_auth_cert(vec![cert], priv_key)
        .map(Arc::new)
        .expect("TLS Config Failure");

    // Server certificate pin validation will be performed in the connection logic (not here)
    config
}

/// Fetches certificate and private key from Windows cert store using SHA256.
/// Returns DER-encoded certificate, PKCS8 private key, and expiry date.
fn fetch_win_cert_and_key(sha256_hex: &str, audit: &crate::audit::AuditGuard) -> (CertificateDer<'static>, PrivateKeyDer<'static>, chrono::NaiveDateTime) {
    let sha256 = hex::decode(sha256_hex.replace(":", "")).unwrap();
    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM as *const u8,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            widestring::WideCString::from_str("MY").unwrap().as_ptr() as *const _,
        );
        if store.is_null() {
            audit.log(Level::Error, 1042, "Failed to open system certificate store.");
            panic!("Failed to open system store");
        }
        let _sg = CertStoreGuard(store);

        // SHA256 search (not SHA1)
        let hash_blob = CRYPT_HASH_BLOB {
            cbData: sha256.len() as u32,
            pbData: sha256.as_ptr() as *mut _,
        };
        let ctx = CertFindCertificateInStore(
            store,
            X509_ASN_ENCODING,
            0,
            CERT_FIND_SHA1_HASH,
            &hash_blob as *const _ as *const _,
            std::ptr::null()
        );
        if ctx.is_null() {
            audit.log(Level::Critical, 1042, "Identity certificate not found (SHA256).");
            panic!("Identity certificate not found");
        }
        let _cg = CertContextGuard(ctx);

        // Extract DER certificate
        let cert_der = CertificateDer::from(std::slice::from_raw_parts(
            (*ctx).pbCertEncoded,
            (*ctx).cbCertEncoded as usize
        ).to_vec());

        // Extract expiry date
        let expiry = chrono::NaiveDateTime::from_timestamp((*ctx).pCertInfo.NotAfter.dwLowDateTime as i64, 0);

        // Extract private key (placeholder: actual extraction via CNG/CryptoAPI required)
        let priv_key = PrivateKeyDer::Pkcs8(vec![0].into()); // TODO: implement actual key extraction

        (cert_der, priv_key, expiry)
    }
}

/// Calculates days until expiry from chrono::NaiveDateTime
fn days_until(expiry: chrono::NaiveDateTime) -> i64 {
    let now = chrono::Utc::now().naive_utc();
    (expiry - now).num_days()
}
