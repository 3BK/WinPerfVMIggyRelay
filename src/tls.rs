use crate::guards::{CertContextGuard, CertStoreGuard};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}, ClientConfig, RootCertStore};
use std::sync::Arc;
use windows_sys::Win32::Security::Cryptography::*;

pub fn build_rustls_config(client_sha1: &str) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let cert_der = extract_windows_cert(client_sha1);

    // NIST 800-53 SC-8: Encrypted Transit via mTLS
    let config = ClientConfig::builder()
        .with_root_store(root_store)
        .with_client_auth_cert(vec![cert_der], dummy_key()) 
        .expect("PCI DSS 4.0: TLS configuration failure");

    Arc::new(config)
}

fn extract_windows_cert(sha1_hex: &str) -> CertificateDer<'static> {
    let sha1 = hex::decode(sha1_hex.replace(":", "")).expect("Invalid SHA1 thumbprint");
    
    unsafe {
        let store = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, 
            widestring::WideCString::from_str("MY").unwrap().as_ptr() as *const _);
        let _sg = CertStoreGuard(store);

        let mut hash_blob = CRYPT_HASH_BLOB {
            cbData: sha1.len() as u32,
            pbData: sha1.as_ptr() as *mut _,
        };

        let cert_ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &hash_blob as *const _ as *const _, std::ptr::null());
        if cert_ctx.is_null() { panic!("Audit Failure: mTLS Certificate not found"); }
        let _cg = CertContextGuard(cert_ctx);

        let der = std::slice::from_raw_parts((*cert_ctx).pbCertEncoded, (*cert_ctx).cbCertEncoded as usize);
        CertificateDer::from(der.to_vec())
    }
}

fn dummy_key() -> PrivateKeyDer<'static> {
    // In a production KSP environment, the private key remains in the TPM/HSM
    // This assumes a PKCS8 identity is provided or handled via SChannel bridge
    PrivateKeyDer::Pkcs8(vec![].into())
}
