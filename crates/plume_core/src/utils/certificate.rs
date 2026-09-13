use std::{fs, path::PathBuf, vec};

use apple_codesign::{
    SigningSettings,
    cryptography::{InMemoryPrivateKey, PrivateKey},
};
// TODO: why do we have pem and pem_rfc7468 deps again?
use pem_rfc7468::{LineEnding, encode_string};
use rand::rngs::OsRng;
use rcgen::{DnType, KeyPair, PKCS_RSA_SHA256};
use rsa::{
    RsaPrivateKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use x509_certificate::{CapturedX509Certificate, X509Certificate};

use crate::{
    Error,
    developer::{DeveloperSession, qh::certs::Cert},
};

pub(crate) const MACHINE_NAME: &str = "AltStore";

pub struct CertificateIdentity {
    pub cert: Option<CapturedX509Certificate>,
    pub key: Option<Box<dyn PrivateKey>>,
    pub machine_id: Option<String>,
    pub serial_number: Option<String>,
    pub p12_data: Option<Vec<u8>>,
    pub new: bool,
}

impl CertificateIdentity {
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.cert
            .as_ref()
            .map(CapturedX509Certificate::constructed_data)
    }

    // Use for cli context or if you actually store pems? why would you do that though
    pub async fn new_with_paths(paths: Option<Vec<PathBuf>>) -> Result<Self, Error> {
        let mut cert = Self {
            cert: None,
            key: None,
            machine_id: None,
            p12_data: None,
            serial_number: None,
            new: false,
        };

        if let Some(paths) = paths {
            for path in &paths {
                let pem_data = fs::read(path)?;
                cert.resolve_certificate_from_contents(pem_data)?;
            }
        }

        Ok(cert)
    }

    pub async fn new_with_session(
        session: &DeveloperSession,
        config_path: PathBuf,
        machine_name: Option<String>,
        team_id: &String,
        is_export: bool,
        on_certificate_reset: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<Self, Error> {
        let machine_name = machine_name.unwrap_or_else(|| MACHINE_NAME.to_string());

        let key_path = Self::key_dir(config_path, &team_id)?.join("key.pem");

        let mut identity = Self {
            cert: None,
            key: None,
            machine_id: None,
            p12_data: None,
            serial_number: None,
            new: false,
        };

        // To same some unnecessary requests, we're going to list our certificates first here
        // then pass them into the necessary functions that need it, if the functions absolutely
        // need to request certificates (after submitting a CSR, for example), they can do so
        let certs = session.qh_list_certs(&team_id).await?.certificates;

        // Only the key will be written to disk, certificate can just be gotten via the request
        // request we've made, by trying to match our public key with the requests public key
        let key_pair: [Vec<u8>; 2] = if key_path.exists() {
            let key_string = fs::read_to_string(&key_path)?;
            let priv_key = RsaPrivateKey::from_pkcs8_pem(&key_string)?;

            if let Some(certificate) = identity
                .find_certificate(certs.clone(), &priv_key, &machine_name)
                .await?
            {
                let cert_pem = encode_string(
                    "CERTIFICATE",
                    LineEnding::LF,
                    certificate
                        .cert_content
                        .ok_or(Error::CertificatePemMissing)?
                        .as_ref(),
                )
                .unwrap();
                let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

                [cert_pem.into_bytes(), key_pem.into_bytes()]
            } else {
                let (certificate, priv_key) = identity
                    .request_new_certificate(
                        session,
                        team_id,
                        &machine_name,
                        certs,
                        on_certificate_reset,
                    )
                    .await?;

                let cert_pem = encode_string(
                    "CERTIFICATE",
                    LineEnding::LF,
                    certificate
                        .cert_content
                        .ok_or(Error::CertificatePemMissing)?
                        .as_ref(),
                )
                .unwrap();
                let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

                fs::write(&key_path, &key_pem)?;
                identity.new = true;
                [cert_pem.into_bytes(), key_pem.into_bytes()]
            }
        } else {
            let (cert, priv_key) = identity
                .request_new_certificate(
                    session,
                    team_id,
                    &machine_name,
                    certs,
                    on_certificate_reset,
                )
                .await?;
            let cert_pem = encode_string(
                "CERTIFICATE",
                LineEnding::LF,
                cert.cert_content
                    .ok_or(Error::CertificatePemMissing)?
                    .as_ref(),
            )
            .unwrap();
            let key_pem = priv_key.to_pkcs8_pem(Default::default())?.to_string();

            fs::write(&key_path, &key_pem)?;
            identity.new = true;
            [cert_pem.into_bytes(), key_pem.into_bytes()]
        };

        // TODO: this may be horrendious
        if let Some(p12_data) = identity.create_pkcs12(&key_pair, is_export) {
            identity.p12_data = Some(p12_data);
        }

        for pem in key_pair {
            identity.resolve_certificate_from_contents(pem)?;
        }

        Ok(identity)
    }

    // <config_path>/keys/<team_id>
    fn key_dir(path: PathBuf, team_id: &String) -> Result<PathBuf, Error> {
        let dir = path.join("keys").join(team_id);

        fs::create_dir_all(&dir)?;

        Ok(dir)
    }

    fn set_machine_id(&mut self, machine_id: String) {
        self.machine_id = Some(machine_id);
    }

    fn set_serial_number(&mut self, serial_number: String) {
        self.serial_number = Some(serial_number);
    }

    // TODO: cleanest p12 code of them all
    // the main horror about p12 creation is that we rely on p12-keystore which is
    // just another unnecessary dependency, but the p12 crate that applecodesign-rs
    // uses has no support for modern encryption, hopefully this doesn't add that
    // much more bloat
    pub fn create_pkcs12(&self, data: &[Vec<u8>; 2], is_export: bool) -> Option<Vec<u8>> {
        let cert_der = pem::parse(&data[0]).ok()?.contents().to_vec();
        let key_der = pem::parse(&data[1]).ok()?.contents().to_vec();

        let cert = p12_keystore::Certificate::from_der(&cert_der).ok()?;

        let local_key_id = {
            use sha1::{Digest, Sha1};
            let mut hasher = Sha1::new();
            hasher.update(&key_der);
            let hash = hasher.finalize();
            hash[..8].to_vec()
        };

        let key_chain = p12_keystore::PrivateKeyChain::new(key_der, local_key_id, vec![cert]);

        let mut keystore = p12_keystore::KeyStore::new();
        keystore.add_entry(
            "plume",
            p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
        );

        // when exporting the user has no idea what the password is, just dont set one
        // otherwise, when not exporting (used for SideStore/AltStore) we use the
        // machine_id since it needs it to locate a matching certificate
        let password = if is_export {
            "".to_string()
        } else {
            self.machine_id.as_deref().unwrap_or("").to_string()
        };

        let writer = keystore.writer(&password);
        writer.write().ok()
    }

    // applecodesign-rs needs our contents as strings to sign
    fn resolve_certificate_from_contents(&mut self, contents: Vec<u8>) -> Result<(), Error> {
        for pem in pem::parse_many(contents).map_err(Error::Pem)? {
            match pem.tag() {
                "CERTIFICATE" => {
                    self.cert = Some(CapturedX509Certificate::from_der(pem.contents())?);
                }
                "PRIVATE KEY" => {
                    self.key = Some(Box::new(InMemoryPrivateKey::from_pkcs8_der(
                        pem.contents(),
                    )?));
                }
                "RSA PRIVATE KEY" => {
                    self.key = Some(Box::new(InMemoryPrivateKey::from_pkcs1_der(
                        pem.contents(),
                    )?));
                }
                tag => log::debug!("(unhandled PEM tag {}; ignoring)", tag),
            }
        }

        Ok(())
    }
}

impl CertificateIdentity {
    async fn find_certificate(
        &mut self,
        certs: Vec<Cert>,
        priv_key: &RsaPrivateKey,
        machine_name: &str,
    ) -> Result<Option<Cert>, Error> {
        let pub_key_der_obj = priv_key.to_public_key().to_pkcs1_der()?.as_bytes().to_vec();

        for cert in certs {
            if cert.machine_name.as_deref() == Some(machine_name) {
                if let Some(cert_content) = &cert.cert_content {
                    let parsed_cert = X509Certificate::from_der(&cert_content)?;
                    if pub_key_der_obj == parsed_cert.public_key_data().as_ref() {
                        // We need to save the machine_id for our P12
                        if let Some(ref machine_id) = cert.machine_id {
                            self.set_machine_id(machine_id.clone());
                        }

                        self.set_serial_number(cert.serial_number.clone());

                        return Ok(Some(cert));
                    }
                }
            }
        }

        Ok(None)
    }

    async fn request_new_certificate(
        &mut self,
        session: &DeveloperSession,
        team_id: &String,
        machine_name: &String,
        certs: Vec<Cert>,
        mut on_certificate_reset: Option<&mut dyn FnMut() -> bool>,
    ) -> Result<(Cert, RsaPrivateKey), Error> {
        let priv_key = RsaPrivateKey::new(&mut OsRng, 2048)?;
        let priv_key_der = priv_key.to_pkcs8_der()?;
        let priv_key_pair = KeyPair::from_der(priv_key_der.as_bytes())?;

        let mut params = rcgen::CertificateParams::new(vec![]);
        params.alg = &PKCS_RSA_SHA256;
        params.key_pair = Some(priv_key_pair);

        let dn = &mut params.distinguished_name;
        dn.push(DnType::CountryName, "US");
        dn.push(DnType::StateOrProvinceName, "STATE");
        dn.push(DnType::LocalityName, "LOCAL");
        dn.push(DnType::OrganizationName, "ORGNIZATION");
        dn.push(DnType::CommonName, "CN");

        let cert_csr = rcgen::Certificate::from_params(params)?.serialize_request_pem()?;

        let cert_serial_numbers = certs
            .iter()
            .map(|c| c.serial_number.clone())
            .collect::<Vec<_>>();
        let mut warned_about_reset = false;

        // When we submit a CSR theres a high chance of it failing, at least
        // on free developer accounts, we put it in a loop so whenever it does
        // fail, we also look through all of our existing certificates through
        // the api until we have a success on a single revokage, then we can
        // successfully submit our csr, but if we just cannot at all, return
        // an error
        let cert_id = loop {
            match session
                .qh_submit_cert_csr(&team_id, cert_csr.clone(), machine_name)
                .await
            {
                Ok(id) => break id,
                Err(e) => {
                    // 7460 is for too many certificates (I think)
                    if matches!(&e, Error::DeveloperApi { result_code, .. } if *result_code == 7460)
                    {
                        if !warned_about_reset {
                            if let Some(callback) = on_certificate_reset.as_deref_mut() {
                                if !callback() {
                                    return Err(Error::Certificate(
                                        "Certificate reset cancelled".into(),
                                    ));
                                }
                            }
                            warned_about_reset = true;
                        }

                        // Try to revoke certificates from the candidate list
                        let mut revoked_any = false;
                        for cid in &cert_serial_numbers {
                            if session.qh_revoke_cert(&team_id, cid).await.is_ok() {
                                log::warn!("Revoked certificate with serial number {}", cid);
                                revoked_any = true;
                                break;
                            }
                        }

                        if revoked_any {
                            continue;
                        } else {
                            return Err(Error::Certificate(
                                "Too many certificates and failed to revoke any".into(),
                            ));
                        }
                    }

                    return Err(e);
                }
            }
        }
        .cert_request;

        // We need to save the machine_id for our P12
        if let Some(ref machine_id) = cert_id.machine_id {
            self.set_machine_id(machine_id.clone());
        }

        self.set_serial_number(cert_id.serial_num.clone());

        // We request again, and hope this has our new certificate
        // ready.... if not then woops... thats too bad isnt it
        let certs = session
            .qh_list_certs(&team_id)
            .await?
            .certificates
            .into_iter()
            .find(|c| c.certificate_id == cert_id.certificate_id);

        Ok((certs.ok_or(Error::CertificatePemMissing)?, priv_key))
    }
}

impl CertificateIdentity {
    pub fn load_into_signing_settings<'settings, 'slf: 'settings>(
        &'slf self,
        settings: &'settings mut SigningSettings<'slf>,
    ) -> Result<(), Error> {
        let signing_cert = self.cert.clone().ok_or(Error::CertificatePemMissing)?;
        let signing_key = self.key.as_ref().ok_or(Error::CertificatePemMissing)?;

        settings.set_signing_key(signing_key.as_key_info_signer(), signing_cert);
        settings.chain_apple_certificates();
        settings.set_team_id_from_signing_certificate();

        Ok(())
    }
}
