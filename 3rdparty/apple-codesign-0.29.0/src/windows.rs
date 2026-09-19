// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Functionality that only works on Windows.

use {
    crate::{
        certificate::AppleCertificate,
        cryptography::PrivateKey,
        error::AppleCodesignError,
        remote_signing::{session_negotiation::PublicKeyPeerDecrypt, RemoteSignError},
    },
    bytes::Bytes,
    log::{error, info, warn},
    signature::Signer,
    std::ops::Deref,
    std::ptr,
    std::slice,
    widestring::U16CString,
    windows_sys::Win32::{
        Foundation::{GetLastError, BOOL},
        Security::Cryptography::*,
    },
    x509_certificate::{
        CapturedX509Certificate, EcdsaCurve, KeyAlgorithm, KeyInfoSigner, Sign, Signature,
        SignatureAlgorithm, X509CertificateError,
    },
    zeroize::Zeroizing,
};

// A wrapper around GetLastError.
fn get_last_error() -> u32 {
    unsafe { GetLastError() }
}

/// A wrapper around [CERT_OPEN_STORE_FLAGS] so we can use crate local types.
#[derive(Clone, Copy, Debug)]
pub enum StoreName {
    CurrentUser,
    LocalMachine,
    CurrentService,
}

impl From<StoreName> for CERT_OPEN_STORE_FLAGS {
    fn from(v: StoreName) -> Self {
        match v {
            StoreName::CurrentUser => {
                CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            StoreName::LocalMachine => {
                CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
            StoreName::CurrentService => {
                CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT
            }
        }
    }
}

impl From<StoreName> for &'static str {
    fn from(v: StoreName) -> Self {
        match v {
            StoreName::CurrentUser => "user",
            StoreName::LocalMachine => "machine",
            StoreName::CurrentService => "service",
        }
    }
}

impl TryFrom<&str> for StoreName {
    type Error = String;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        match v.to_lowercase().as_str() {
            "user" => Ok(Self::CurrentUser),
            "machine" => Ok(Self::LocalMachine),
            "service" => Ok(Self::CurrentService),
            _ => Err(format!(
                "{} is not a valid windows store name; use user, machine or service",
                v
            )),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum StoreType {
    CA,
    MY,
    ROOT,
    SPC,
}

impl From<StoreType> for &'static str {
    fn from(v: StoreType) -> Self {
        match v {
            StoreType::CA => "ca",
            StoreType::MY => "my",
            StoreType::ROOT => "root",
            StoreType::SPC => "spc",
        }
    }
}

impl TryFrom<&str> for StoreType {
    type Error = String;

    fn try_from(v: &str) -> Result<Self, Self::Error> {
        match v.to_lowercase().as_str() {
            "ca" => Ok(Self::CA),
            "my" => Ok(Self::MY),
            "root" => Ok(Self::ROOT),
            "spc" => Ok(Self::SPC),
            _ => Err(format!(
                "{} is not a valid windows store type; use ca, my, root or spc",
                v
            )),
        }
    }
}

/// A certificate in a Windows store.
#[derive(Clone)]
pub struct StoreCertificate {
    cert_context: *mut CERT_CONTEXT,
    cert_thumbprint: String,
    hkey: NCRYPT_KEY_HANDLE,
    must_free_hkey: bool,
    captured: CapturedX509Certificate,
}

impl StoreCertificate {
    fn new(cert_context: *mut CERT_CONTEXT) -> Result<StoreCertificate, AppleCodesignError> {
        if cert_context.is_null() {
            return Err(AppleCodesignError::WindowsStoreError(
                "certificate context is null".into(),
            ));
        }

        let cert_der = unsafe {
            slice::from_raw_parts(
                (*cert_context).pbCertEncoded,
                (*cert_context).cbCertEncoded as usize,
            )
        }
        .to_vec();

        let captured = CapturedX509Certificate::from_der(cert_der)?;
        let cert_thumbprint = hex::encode(captured.sha1_fingerprint()?.as_ref());

        // We try to get either a CNG or a CryptoAPI handle.
        // CryptAcquireCertificatePrivateKey can fail if the certificate does
        // not have a private key (for example if it is a CA certificate).
        // Therefore, we do not return an error if that happens.

        let mut hkey = 0;
        let mut must_free_hkey = false;
        let mut hprov_ncryptkey_handle = HCRYPTPROV_OR_NCRYPT_KEY_HANDLE::default();
        let mut key_spec = CERT_KEY_SPEC::default();
        let mut must_free_hprov_ncryptkey_handle = BOOL::default();
        let result = unsafe {
            CryptAcquireCertificatePrivateKey(
                cert_context,
                CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG, // Prefer CNG keys, but accept CryptoAPI keys if CNG is not available.
                ptr::null_mut(),
                &mut hprov_ncryptkey_handle,
                &mut key_spec,
                &mut must_free_hprov_ncryptkey_handle,
            )
        } != 0;
        if result {
            if key_spec != CERT_NCRYPT_KEY_SPEC {
                // The key is linked to a CryptoAPI provider (CSP).
                // Because the use of CryptoAPI providers is deprecated, and because
                // most CryptoAPI providers do not support SHA-2, we need to translate
                // the CryptoAPI handle to get a CNG key handle by using NCryptTranslateHandle.
                // The translation will fail if there is no CNG provider that
                // is registered with a name or alias that matches the name of the CryptoAPI
                // provider. If that happens, then the certificate is simply unusable for
                // signing / decryption.

                let result = unsafe {
                    NCryptTranslateHandle(
                        ptr::null_mut(),
                        &mut hkey,
                        hprov_ncryptkey_handle,
                        0,
                        key_spec,
                        0,
                    )
                };
                if result == 0 {
                    must_free_hkey = true; // Always true if we were able translate the handle.
                } else {
                    info!(
                        "could not translate the private key for certificate {} (0x{:08X})",
                        cert_thumbprint, result
                    );
                }

                // We can now release the CryptoAPI handle if we are instructed to do so.
                if must_free_hprov_ncryptkey_handle == 1 {
                    unsafe {
                        CryptReleaseContext(hprov_ncryptkey_handle, 0);
                    }
                }
            } else {
                // The key is linked to a CNG provider (KSP).
                // We can use the handle as is.
                hkey = hprov_ncryptkey_handle;
                must_free_hkey = must_free_hprov_ncryptkey_handle == 1;
            }
        } else {
            info!(
                "could not acquire the private key for certificate {} (0x{:08X})",
                cert_thumbprint,
                get_last_error()
            );
        }

        Ok(StoreCertificate {
            cert_context: unsafe { CertDuplicateCertificateContext(cert_context) },
            cert_thumbprint,
            hkey,
            must_free_hkey,
            captured,
        })
    }
}

impl Drop for StoreCertificate {
    fn drop(&mut self) {
        if self.hkey != NCRYPT_KEY_HANDLE::default() && self.must_free_hkey {
            unsafe { NCryptFreeObject(self.hkey) };
        }
        if self.cert_context != ptr::null_mut() {
            unsafe { CertFreeCertificateContext(self.cert_context) };
        }
    }
}

impl Deref for StoreCertificate {
    type Target = CapturedX509Certificate;

    fn deref(&self) -> &Self::Target {
        &self.captured
    }
}

impl Signer<Signature> for StoreCertificate {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        // First, we need to ensure that the signer has a private key.
        if self.hkey == NCRYPT_KEY_HANDLE::default() {
            return Err(signature::Error::from_source(format!(
                "certificate {} does not have a private key",
                self.cert_thumbprint
            )));
        }

        if let Some(cn) = self.captured.subject_common_name() {
            warn!(
                "attempting to create signature using Windows store certificate: {} ({})",
                cn, self.cert_thumbprint
            );
        } else {
            warn!(
                "attempting to create signature using Windows store certificate: {}",
                self.cert_thumbprint
            );
        }

        let signature_algorithm = self
            .signature_algorithm()
            .map_err(signature::Error::from_source)?;

        // We need to set the padding for NcryptSignHash.
        // Note that ECDSA signatures do not need
        // padding, so it is fine to set this to null.
        let (padding_info, flags) = match signature_algorithm {
            SignatureAlgorithm::RsaSha1 => (
                &mut BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA1_ALGORITHM as *mut u16,
                } as *mut BCRYPT_PKCS1_PADDING_INFO,
                NCRYPT_PAD_PKCS1_FLAG,
            ),
            SignatureAlgorithm::RsaSha256 => (
                &mut BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA256_ALGORITHM as *mut u16,
                } as *mut BCRYPT_PKCS1_PADDING_INFO,
                NCRYPT_PAD_PKCS1_FLAG,
            ),
            SignatureAlgorithm::RsaSha384 => (
                &mut BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA384_ALGORITHM as *mut u16,
                } as *mut BCRYPT_PKCS1_PADDING_INFO,
                NCRYPT_PAD_PKCS1_FLAG,
            ),
            SignatureAlgorithm::RsaSha512 => (
                &mut BCRYPT_PKCS1_PADDING_INFO {
                    pszAlgId: BCRYPT_SHA512_ALGORITHM as *mut u16,
                } as *mut BCRYPT_PKCS1_PADDING_INFO,
                NCRYPT_PAD_PKCS1_FLAG,
            ),
            SignatureAlgorithm::EcdsaSha256 => {
                (ptr::null_mut() as *mut BCRYPT_PKCS1_PADDING_INFO, 0)
            }
            SignatureAlgorithm::EcdsaSha384 => {
                (ptr::null_mut() as *mut BCRYPT_PKCS1_PADDING_INFO, 0)
            }
            SignatureAlgorithm::Ed25519 => {
                return Err(signature::Error::from_source(
                    "ed25519 not supported on windows",
                ));
            }
            SignatureAlgorithm::NoSignature(_) => {
                return Err(signature::Error::from_source("digest only signature"));
            }
        };

        let key_algorithm = self
            .key_algorithm()
            .ok_or(X509CertificateError::UnknownDigestAlgorithm(
                "failed to resolve key algorithm for certificate".into(),
            ))
            .map_err(signature::Error::from_source)?;

        let digest_algorithm = signature_algorithm
            .digest_algorithm()
            .ok_or(X509CertificateError::UnknownDigestAlgorithm(
                "unable to resolve digest algorithm from signature algorithm".into(),
            ))
            .map_err(signature::Error::from_source)?;

        // We need to create the hash over the message.
        let hash = match key_algorithm {
            KeyAlgorithm::Rsa => digest_algorithm.digest_data(message),
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp256r1) => digest_algorithm.digest_data(message),
            KeyAlgorithm::Ecdsa(EcdsaCurve::Secp384r1) => digest_algorithm.digest_data(message),
            KeyAlgorithm::Ed25519 => {
                return Err(signature::Error::from_source(
                    "ed25519 not supported on windows",
                ));
            }
        };

        // We sign using NCryptSignHash.
        let mut signature: Vec<u8> = Vec::new();
        let mut signature_len: u32 = 0;
        let result = unsafe {
            NCryptSignHash(
                self.hkey,
                padding_info as *mut core::ffi::c_void,
                hash.as_ptr(),
                hash.len() as u32,
                ptr::null_mut(),
                0,
                &mut signature_len,
                flags,
            )
        };
        if result != 0 {
            return Err(signature::Error::from_source(format!("error when attempting to create signature with certificate {} (NCryptSignHash 1): 0x{:08X}", self.cert_thumbprint, result)));
        }
        signature.resize(signature_len as usize, 0);
        let result = unsafe {
            NCryptSignHash(
                self.hkey,
                padding_info as *mut core::ffi::c_void,
                hash.as_ptr(),
                hash.len() as u32,
                signature.as_mut_ptr(),
                signature.len() as u32,
                &mut signature_len,
                flags,
            )
        };
        if result != 0 {
            return Err(signature::Error::from_source(format!("error when attempting to create signature with certificate {} (NCryptSignHash 2): 0x{:08X}", self.cert_thumbprint, result)));
        }
        signature.resize(signature_len as usize, 0);

        return Ok(Signature::from(signature));
    }
}

impl Sign for StoreCertificate {
    fn sign(&self, message: &[u8]) -> Result<(Vec<u8>, SignatureAlgorithm), X509CertificateError> {
        let algorithm = self.signature_algorithm()?;

        Ok((self.try_sign(message)?.into(), algorithm))
    }

    fn key_algorithm(&self) -> Option<KeyAlgorithm> {
        self.captured.key_algorithm()
    }

    fn public_key_data(&self) -> Bytes {
        self.captured.public_key_data()
    }

    fn signature_algorithm(&self) -> Result<SignatureAlgorithm, X509CertificateError> {
        self.captured
            .signature_algorithm()
            .ok_or(X509CertificateError::UnknownSignatureAlgorithm(format!(
                "{:?}",
                self.captured.signature_algorithm_oid()
            )))
    }

    fn private_key_data(&self) -> Option<Zeroizing<Vec<u8>>> {
        None
    }

    fn rsa_primes(
        &self,
    ) -> Result<Option<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>, X509CertificateError> {
        Ok(None)
    }
}

impl KeyInfoSigner for StoreCertificate {}

impl PublicKeyPeerDecrypt for StoreCertificate {
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, RemoteSignError> {
        // First, we need to check if the signer has a private key.
        if self.hkey == NCRYPT_KEY_HANDLE::default() {
            return Err(RemoteSignError::Crypto(
                "certificate does not have a private key".into(),
            ));
        }

        if let Some(cn) = self.captured.subject_common_name() {
            warn!(
                "attempting to decrypt using Windows store certificate: {} ({})",
                cn, self.cert_thumbprint
            );
        } else {
            warn!(
                "attempting to decrypt using Windows store certificate: {}",
                self.cert_thumbprint
            );
        }

        // We set the OAEP padding info.
        let padding_info: *mut BCRYPT_OAEP_PADDING_INFO = &mut BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM as *mut u16,
            cbLabel: 0,
            pbLabel: ptr::null_mut(),
        };

        // We decrypt using NCryptDecrypt.
        let mut plaintext: Vec<u8> = Vec::new();
        let mut plaintext_len: u32 = 0;
        let result = unsafe {
            NCryptDecrypt(
                self.hkey,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                padding_info as *mut core::ffi::c_void,
                ptr::null_mut(),
                0,
                &mut plaintext_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if result != 0 {
            return Err(RemoteSignError::Crypto(format!("error when attempting to decrypt ciphertext with certificate {} (NCryptDecrypt 1): 0x{:08X}", self.cert_thumbprint, result)));
        }
        plaintext.resize(plaintext_len as usize, 0);
        let result = unsafe {
            NCryptDecrypt(
                self.hkey,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                padding_info as *mut core::ffi::c_void,
                plaintext.as_mut_ptr(),
                plaintext.len() as u32,
                &mut plaintext_len,
                BCRYPT_PAD_OAEP,
            )
        };
        if result != 0 {
            return Err(RemoteSignError::Crypto(format!("error when attempting to decrypt ciphertext with certificate {} (NCryptDecrypt 2): 0x{:08X}", self.cert_thumbprint, result)));
        }
        plaintext.resize(plaintext_len as usize, 0);

        return Ok(plaintext);
    }
}

impl PrivateKey for StoreCertificate {
    fn as_key_info_signer(&self) -> &dyn KeyInfoSigner {
        self
    }

    fn to_public_key_peer_decrypt(
        &self,
    ) -> Result<Box<dyn PublicKeyPeerDecrypt>, AppleCodesignError> {
        Ok(Box::new(self.clone()))
    }

    fn finish(&self) -> Result<(), AppleCodesignError> {
        Ok(())
    }
}

impl StoreCertificate {
    /// Obtain a new [CapturedX509Certificate] for this item.
    pub fn as_captured_x509_certificate(&self) -> CapturedX509Certificate {
        self.captured.clone()
    }
}

fn find_certificates(
    store_name: StoreName,
    store_type: StoreType,
) -> Result<Vec<StoreCertificate>, AppleCodesignError> {
    let mut certs = vec![];

    let store_type_str: &'static str = store_type.into();
    let store_name_str: &'static str = store_name.into();

    let store_type_wstr = U16CString::from_str(store_type_str).map_err(|_| {
        AppleCodesignError::WindowsStoreError(format!(
            "could not convert store type {} to wide string (this should not happen)",
            store_type_str
        ))
    })?;

    let dwflags = CERT_OPEN_STORE_FLAGS::from(store_name);

    // Open the certificate store.
    let store_handle = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_SYSTEM_W as _,
            X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
            HCRYPTPROV_LEGACY::default(),
            dwflags | CERT_STORE_OPEN_EXISTING_FLAG,
            store_type_wstr.as_ptr() as _,
        )
    };
    if store_handle.is_null() {
        return Err(AppleCodesignError::WindowsStoreError(format!(
            "could not open store {} with store type {} (this should not happen): 0x{:08X}",
            store_name_str,
            store_type_str,
            get_last_error()
        )));
    }

    // Enumerate the certificates.
    let mut cert_context = ptr::null_mut();
    loop {
        // Get the next certificate.
        cert_context = unsafe {
            CertFindCertificateInStore(
                store_handle,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                0,
                CERT_FIND_ANY,
                ptr::null_mut(),
                cert_context,
            )
        };
        if cert_context.is_null() {
            break;
        }

        match StoreCertificate::new(cert_context) {
            Ok(cert) => certs.push(cert),
            Err(err) => {
                error!(
                    "failed to create Windows store certificate for certificate ({})",
                    err
                );
            }
        };
    }

    // Close the store.
    unsafe { CertCloseStore(store_handle, 0) };

    Ok(certs)
}

/// Locate code signing certificates in the Windows store.
/// Since end user certificates are normally located in the `MY` store,
/// we hard-code the store type to `MY`.
/// We also only return certificates that have the `Apple Code Signing` extension
/// and a valid private key.
pub fn windows_store_find_code_signing_certificates(
    store_name: StoreName,
) -> Result<Vec<StoreCertificate>, AppleCodesignError> {
    let certs = find_certificates(store_name, StoreType::MY)?;

    Ok(certs
        .into_iter()
        .filter(|cert| {
            !cert.captured.apple_code_signing_extensions().is_empty()
                && cert.hkey != NCRYPT_KEY_HANDLE::default()
        })
        .collect::<Vec<_>>())
}

/// Find the x509 certificate chain for a certificate given search parameters.
///
/// `store_name` specifies which store to operate on.
///
/// `sha1_fingerprint` specifies the SHA1 digest of the certificate to search for.
/// You can find this in `certmgr.msc` or `certlm.msc` by clicking on the certificate in
/// question and looking for `Thumbprint` under the `Details` tab.
pub fn windows_store_find_certificate_chain(
    store_name: StoreName,
    sha1_fingerprint: &str,
) -> Result<Vec<CapturedX509Certificate>, AppleCodesignError> {
    // We look for the code signing certificate in the MY store.
    let user_certs = find_certificates(store_name, StoreType::MY)?;

    // Now search for the requested start certificate and pull the thread until
    // we get to a self-signed certificate.
    let start_cert: &CapturedX509Certificate = user_certs
        .iter()
        .find_map(|cert| {
            if let Ok(digest) = cert.captured.sha1_fingerprint() {
                // Convert the Digest into a byte array
                let digest_bytes = digest.as_ref();

                // Get the hex representation of the digest
                let digest_hex: String = hex::encode(digest_bytes);

                if digest_hex.to_lowercase() == sha1_fingerprint.to_lowercase() {
                    Some(&cert.captured)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .ok_or_else(|| {
            AppleCodesignError::CertificateNotFound(format!("Thumbprint={}", sha1_fingerprint))
        })?;

    // We look for the certificate chain in the CA and ROOT Stores.
    let ca_certs = find_certificates(store_name, StoreType::CA)?
        .into_iter()
        .chain(find_certificates(store_name, StoreType::ROOT)?.into_iter())
        .collect::<Vec<_>>();

    let chain = std::iter::once(start_cert.clone())
        .chain(
            start_cert
                .resolve_signing_chain(ca_certs.iter().map(|cert| &cert.captured))
                .into_iter()
                .cloned(),
        )
        .collect::<Vec<_>>();

    Ok(chain)
}
