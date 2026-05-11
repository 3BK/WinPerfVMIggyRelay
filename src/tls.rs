use crate::audit::AuditGuard;

use log::Level;
use rustls::client::danger::{DangerousClientConfigBuilder, ServerCertVerifier, ServerCertVerified};
use rustls::client::{ResolvesClientCert};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::sign::{CertifiedKey, SignError, Signer, SigningKey};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, HandshakeSignatureValid,
    RootCertStore, SignatureAlgorithm, SignatureScheme,
};
use rustls::client::WebPkiServerVerifier;

use sha2::{Digest, Sha256};
use std::ffi::CStr;
use std::fmt;
use std::ptr;
use std::sync::Arc;

use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Security::Cryptography::*;

/// ==========================
/// RAII (SecureGuard) helpers
/// ==========================

struct SecureCertStore(HCERTSTORE);
impl Drop for SecureCertStore {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                CertCloseStore(self.0, 0);
            }
        }
    }
}

struct SecureCertContext(*const CERT_CONTEXT);
impl Drop for SecureCertContext {
    fn drop(&mut self) {
        unsafe {
            if !self.0.is_null() {
                CertFreeCertificateContext(self.0);
            }
        }
    }
}

/// Per CryptAcquireCertificatePrivateKey contract:
/// free the handle only when pfCallerFreeProvOrNCryptKey is TRUE. 【1-9cd49b】
struct SecureNcryptKey {
    h: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE,
    caller_must_free: bool,
}
impl Drop for SecureNcryptKey {
    fn drop(&mut self) {
        unsafe {
            if self.caller_must_free && self.h != 0 {
                let _ = NCryptFreeObject(self.h);
            }
        }
    }
}

/// Windows typedef alias not always present in windows-sys.
#[repr(C)]
struct CRYPT_DATA_BLOB_REPR {
    cbData: u32,
    pbData: *mut u8,
}

/// ==========================
/// Public entry point
/// ==========================

/// Build rustls ClientConfig with:
/// - ECDSA client auth using CNG key handle (mTLS) (non-exportable key).
/// - Server certificate pinning (SHA-256 of end-entity DER) using dangerous()/custom verifier.
///
/// rustls supports custom key usage via SigningKey/Signer extension points. 【9-f57111】【10-3aff9c】
/// Custom server verification is done via dangerous().with_custom_certificate_verifier(). 【5-5196ea】【6-43a02a】
pub fn build_rustls_config(
    client_cert_sha1_thumbprint: &str,
    server_cert_sha256_pin_hex: &str,
    audit: &AuditGuard,
) -> Arc<ClientConfig> {
    // Parse the configured pin (hex -> [u8; 32])
    let pin = match parse_sha256_pin(server_cert_sha256_pin_hex) {
        Ok(p) => p,
        Err(e) => {
            audit.log(Level::Error, 1041, &format!("Invalid server SHA256 pin: {e}"));
            panic!("Invalid server SHA256 pin: {e}");
        }
    };

    // Build trust roots (still used by WebPkiServerVerifier)
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Provider (aws-lc-rs)
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());

    // Build the default WebPKI verifier (normal PKI validation)
    let webpki = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .expect("failed to build WebPkiServerVerifier");

    // Wrap it with pin enforcement
    let verifier: Arc<dyn ServerCertVerifier> = Arc::new(PinnedWebPkiVerifier {
        inner: webpki,
        expected_pin: pin,
    });

    // Load client mTLS identity (ECDSA CNG key)
    let client_key = match load_ecdsa_cng_identity_from_localmachine_my(client_cert_sha1_thumbprint, audit) {
        Ok(k) => k,
        Err(e) => {
            audit.log(Level::Error, 1042, &format!("mTLS identity load failed: {e}"));
            panic!("mTLS identity load failed: {e}");
        }
    };

    // Build ClientConfig:
    // - choose protocol versions
    // - use dangerous() to set custom verifier
    // - provide client cert resolver (mTLS)
    //
    // ConfigBuilder supports dangerous().with_custom_certificate_verifier(...) for client verification. 【5-5196ea】【11-198614】
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls provider/version configuration error")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(Arc::new(FixedClientCertResolver { key: client_key }));

    Arc::new(cfg)
}

/// ==========================
/// Custom server verifier (WebPKI + pinning)
/// ==========================

#[derive(Debug)]
struct PinnedWebPkiVerifier {
    inner: Arc<WebPkiServerVerifier>,
    expected_pin: [u8; 32], // SHA256 of end-entity cert DER
}

impl ServerCertVerifier for PinnedWebPkiVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // 1) Perform normal WebPKI verification first (DNS name, validity, trust chain, etc.)
        // WebPkiServerVerifier implements ServerCertVerifier. 【7-46b1fe】【6-43a02a】
        let verified = self
            .inner
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)?;

        // 2) Enforce pin on end-entity certificate DER
        let actual = Sha256::digest(end_entity.as_ref());
        if !ct_eq_32(actual.as_slice(), &self.expected_pin) {
            return Err(RustlsError::General(
                "server certificate pin mismatch".to_string(),
            ));
        }

        Ok(verified)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Constant-time compare for 32-byte secrets (pin).
fn ct_eq_32(a: &[u8], b32: &[u8; 32]) -> bool {
    if a.len() != 32 {
        return false;
    }
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b32[i];
    }
    diff == 0
}

fn parse_sha256_pin(pin_hex: &str) -> Result<[u8; 32], String> {
    let cleaned = pin_hex.replace(":", "").trim().to_string();
    let bytes = hex::decode(cleaned).map_err(|e| format!("hex decode failed: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes (64 hex chars), got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// ==========================
/// rustls client certificate resolver
/// ==========================

#[derive(Debug)]
struct FixedClientCertResolver {
    key: Arc<CertifiedKey>,
}

impl ResolvesClientCert for FixedClientCertResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // Present cert only if we can choose a scheme compatible with the server’s offer. 【2-9b06db】
        if self.key.key.choose_scheme(sigschemes).is_some() {
            Some(self.key.clone())
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        true
    }
}

/// ==========================
/// ECDSA CNG-backed SigningKey/Signer
/// ==========================

#[derive(Clone)]
struct CngEcdsaSigningKey {
    ncrypt: Arc<SecureNcryptKey>,
}

impl fmt::Debug for CngEcdsaSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CngEcdsaSigningKey").finish()
    }
}

impl SigningKey for CngEcdsaSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        // Prefer strongest offered ECDSA scheme first (assumption: cert matches).
        // rustls requires choosing from offered SignatureSchemes. 【9-f57111】【10-3aff9c】
        let prefs = [
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP521_SHA512,
        ];

        for p in prefs {
            if offered.iter().any(|&x| x == p) {
                return Some(Box::new(CngEcdsaSigner {
                    ncrypt: self.ncrypt.clone(),
                    scheme: p,
                }));
            }
        }
        None
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Clone)]
struct CngEcdsaSigner {
    ncrypt: Arc<SecureNcryptKey>,
    scheme: SignatureScheme,
}

impl fmt::Debug for CngEcdsaSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CngEcdsaSigner")
            .field("scheme", &self.scheme)
            .finish()
    }
}

impl Signer for CngEcdsaSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SignError> {
        // rustls gives us the message to sign (TLS transcript hash). 【9-f57111】
        sign_ecdsa(self.ncrypt.h, message).map_err(|_| SignError::new())
    }

    fn scheme(&self) -> SignatureScheme {
        self.scheme
    }
}

fn sign_ecdsa(hkey: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, hash: &[u8]) -> Result<Vec<u8>, ()> {
    unsafe {
        let mut sig_len: u32 = 0;
        let st = NCryptSignHash(
            hkey,
            ptr::null_mut(),
            hash.as_ptr() as *mut u8,
            hash.len() as u32,
            ptr::null_mut(),
            0,
            &mut sig_len,
            0,
        );
        if st != 0 {
            return Err(());
        }

        let mut sig = vec![0u8; sig_len as usize];
        let st2 = NCryptSignHash(
            hkey,
            ptr::null_mut(),
            hash.as_ptr() as *mut u8,
            hash.len() as u32,
            sig.as_mut_ptr(),
            sig.len() as u32,
            &mut sig_len,
            0,
        );
        if st2 != 0 {
            return Err(());
        }
        sig.truncate(sig_len as usize);

        // Many CNG ECDSA providers return raw r||s; TLS expects DER.
        if sig.first().copied() == Some(0x30) {
            Ok(sig)
        } else {
            ecdsa_raw_to_der(&sig).ok_or(())
        }
    }
}

fn ecdsa_raw_to_der(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.is_empty() || raw.len() % 2 != 0 {
        return None;
    }
    let half = raw.len() / 2;
    let r = &raw[..half];
    let s = &raw[half..];

    fn int_der(mut x: &[u8]) -> Vec<u8> {
        while x.len() > 1 && x[0] == 0x00 {
            x = &x[1..];
        }
        let needs_pad = (x[0] & 0x80) != 0;
        let mut out = Vec::new();
        out.push(0x02);
        out.push((x.len() + if needs_pad { 1 } else { 0 }) as u8);
        if needs_pad {
            out.push(0x00);
        }
        out.extend_from_slice(x);
        out
    }

    let r_der = int_der(r);
    let s_der = int_der(s);

    let total = r_der.len() + s_der.len();
    let mut seq = Vec::new();
    seq.push(0x30);
    if total < 128 {
        seq.push(total as u8);
    } else {
        let len_bytes = (total as u32).to_be_bytes();
        let mut i = 0;
        while i < len_bytes.len() && len_bytes[i] == 0 {
            i += 1;
        }
        let lb = &len_bytes[i..];
        seq.push(0x80 | (lb.len() as u8));
        seq.extend_from_slice(lb);
    }
    seq.extend_from_slice(&r_der);
    seq.extend_from_slice(&s_der);
    Some(seq)
}

/// ==========================
/// Windows cert store loading (CNG)
/// ==========================

fn load_ecdsa_cng_identity_from_localmachine_my(
    sha1_thumbprint_hex: &str,
    audit: &AuditGuard,
) -> Result<Arc<CertifiedKey>, String> {
    let sha1 = hex::decode(sha1_thumbprint_hex.replace(":", ""))
        .map_err(|e| format!("invalid SHA1 thumbprint hex: {e}"))?;

    unsafe {
        let store = CertOpenStore(
            CERT_STORE_PROV_SYSTEM as *const u8,
            0,
            0,
            CERT_SYSTEM_STORE_LOCAL_MACHINE,
            widestring::WideCString::from_str("MY")
                .map_err(|e| format!("WideCString: {e}"))?
                .as_ptr() as *const _,
        );
        if store.is_null() {
            return Err("failed to open LocalMachine\\MY".into());
        }
        let _store_guard = SecureCertStore(store);

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
            ptr::null(),
        );

        if ctx.is_null() {
            return Err("certificate not found by SHA1 thumbprint".into());
        }
        let _ctx_guard = SecureCertContext(ctx);

        // Optional sanity check: ensure certificate public key algorithm OID is EC.
        if !cert_is_ec(ctx) {
            audit.log(Level::Warn, 1040, "Client certificate does not appear to be EC; assuming ECDSA anyway.");
        }

        // Acquire private key (CNG only, silent)
        let mut key_handle: HCRYPTPROV_OR_NCRYPT_KEY_HANDLE = 0;
        let mut key_spec: u32 = 0;
        let mut caller_free: BOOL = 0;

        let flags = CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG;

        let ok = CryptAcquireCertificatePrivateKey(
            ctx as *const CERT_CONTEXT,
            flags,
            ptr::null_mut(),
            &mut key_handle,
            &mut key_spec,
            &mut caller_free,
        );

        if ok == 0 || key_handle == 0 {
            return Err("CryptAcquireCertificatePrivateKey failed".into());
        }

        if key_spec != CERT_NCRYPT_KEY_SPEC {
            return Err("certificate private key is not CNG (CERT_NCRYPT_KEY_SPEC mismatch)".into());
        }

        let ncrypt = Arc::new(SecureNcryptKey {
            h: key_handle,
            caller_must_free: caller_free != 0,
        });

        // Leaf cert only (you said Pingora doesn't need full chain).
        let der = std::slice::from_raw_parts((*ctx).pbCertEncoded, (*ctx).cbCertEncoded as usize).to_vec();
        let cert_chain = vec![CertificateDer::from(der)];

        let signing_key: Arc<dyn SigningKey> = Arc::new(CngEcdsaSigningKey { ncrypt });

        // CertifiedKey bundles cert chain and SigningKey. 【3-6ee805】
        Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
    }
}

fn cert_is_ec(ctx: *const CERT_CONTEXT) -> bool {
    unsafe {
        let cert_info = (*ctx).pCertInfo;
        if cert_info.is_null() {
            return false;
        }
        let oid_ptr = (*cert_info).SubjectPublicKeyInfo.Algorithm.pszObjId;
        if oid_ptr.is_null() {
            return false;
        }
        let oid = CStr::from_ptr(oid_ptr).to_string_lossy();
        // EC public key: 1.2.840.10045.2.1
        oid == "1.2.840.10045.2.1"
    }
}
