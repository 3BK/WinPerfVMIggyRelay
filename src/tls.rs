use crate::guards::{CertContextGuard, CertStoreGuard};
use rustls::{pki_types::{CertificateDer, PrivateKeyDer}, ClientConfig, RootCertStore};
use std::sync::Arc;
use windows_sys::Win32::Security::Cryptography::*;

pub fn build_rustls_config(client_sha1: &str) -> Arc<ClientConfig> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let cert = fetch_win_cert(client_sha1);
    
    // Fix E0599: rustls 0.23 requires an explicit crypto provider 
    ClientConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .expect("Provider error")
        .with_root_store(root_store)
        .with_client_auth_cert(vec![cert], PrivateKeyDer::Pkcs8(vec![0].into()))
        .map(Arc::new)
        .expect("TLS Config Failure")
}

fn fetch_win_cert(sha1_hex: &str) -> CertificateDer<'static> {
    let sha1 = hex::decode(sha1_hex.replace(":", "")).unwrap();
    unsafe {
        // Fix E0308: Cast CERT_STORE_PROV_SYSTEM to *const u8 (PCSTR) [cite: 13, 14, 15, 16]
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM as *const u8, 
            0, 
            0, 
            CERT_SYSTEM_STORE_LOCAL_MACHINE, 
            widestring::WideCString::from_str("MY").unwrap().as_ptr() as *const _
        );
        
        if store.is_null() { panic!("Failed to open system store"); }
        let _sg = CertStoreGuard(store);

        // Fix E0063: Add missing cUnusedBits field for CRYPT_BIT_BLOB 
        let hash_blob = CRYPT_BIT_BLOB { 
            cbData: sha1.len() as u32, 
            pbData: sha1.as_ptr() as *mut _,
            cUnusedBits: 0, 
        };

        let ctx = CertFindCertificateInStore(
            store, 
            X509_ASN_ENCODING, 
            0, 
            CERT_FIND_SHA1_HASH, 
            &hash_blob as *const _ as *const _, 
            std::ptr::null()
        );
        
        if ctx.is_null() { panic!("Identity certificate not found"); }
        let _cg = CertContextGuard(ctx);
        
        CertificateDer::from(std::slice::from_raw_parts(
            (*ctx).pbCertEncoded, 
            (*ctx).cbCertEncoded as usize
        ).to_vec())
    }
}
