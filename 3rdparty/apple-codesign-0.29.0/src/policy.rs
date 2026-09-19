// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Apple trust policies.
//!
//! Apple operating systems have a number of pre-canned trust policies
//! that must be fulfilled in order to trust signed code. These are
//! often based off the presence of specific X.509 certificates in the
//! issuing chain and/or the presence of attributes in X.509 certificates.
//!
//! Trust policies are often engraved in code signatures as part of the
//! signed code requirements expression.
//!
//! This module defines a bunch of metadata for describing Apple trust
//! entities and also provides pre-canned policies that can be easily
//! constructed to match those employed by Apple's official signing tools.
//!
//! Apple's certificates can be found at
//! <https://www.apple.com/certificateauthority/>.

use {
    crate::{
        certificate::{
            AppleCertificate, CertificateAuthorityExtension, CodeSigningCertificateExtension,
        },
        code_requirement::{CodeRequirementExpression, CodeRequirementMatchExpression},
        error::AppleCodesignError,
    },
    once_cell::sync::Lazy,
    std::ops::Deref,
    x509_certificate::CapturedX509Certificate,
};

/// Code signing requirement for Mac Developer ID.
///
/// `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and
/// (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate leaf[field.1.2.840.113635.100.6.1.13])`
static POLICY_MAC_DEVELOPER_ID: Lazy<CodeRequirementExpression<'static>> = Lazy::new(|| {
    CodeRequirementExpression::And(
        Box::new(CodeRequirementExpression::And(
            Box::new(CodeRequirementExpression::AnchorAppleGeneric),
            Box::new(CodeRequirementExpression::CertificateGeneric(
                1,
                CertificateAuthorityExtension::DeveloperId.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
        )),
        Box::new(CodeRequirementExpression::Or(
            Box::new(CodeRequirementExpression::CertificateGeneric(
                0,
                CodeSigningCertificateExtension::DeveloperIdInstaller.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
            Box::new(CodeRequirementExpression::CertificateGeneric(
                0,
                CodeSigningCertificateExtension::DeveloperIdApplication.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
        )),
    )
});

/// Notarized executable.
///
/// `anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and
/// certificate leaf[field.1.2.840.113635.100.6.1.13] exists and notarized'`
///
static POLICY_NOTARIZED_EXECUTABLE: Lazy<CodeRequirementExpression<'static>> = Lazy::new(|| {
    CodeRequirementExpression::And(
        Box::new(CodeRequirementExpression::And(
            Box::new(CodeRequirementExpression::And(
                Box::new(CodeRequirementExpression::AnchorAppleGeneric),
                Box::new(CodeRequirementExpression::CertificateGeneric(
                    1,
                    CertificateAuthorityExtension::DeveloperId.as_oid(),
                    CodeRequirementMatchExpression::Exists,
                )),
            )),
            Box::new(CodeRequirementExpression::CertificateGeneric(
                0,
                CodeSigningCertificateExtension::DeveloperIdApplication.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
        )),
        Box::new(CodeRequirementExpression::Notarized),
    )
});

/// Notarized installer.
///
/// `'anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists
/// and (certificate leaf[field.1.2.840.113635.100.6.1.14] or certificate
/// leaf[field.1.2.840.113635.100.6.1.13]) and notarized'`
static POLICY_NOTARIZED_INSTALLER: Lazy<CodeRequirementExpression<'static>> = Lazy::new(|| {
    CodeRequirementExpression::And(
        Box::new(CodeRequirementExpression::And(
            Box::new(CodeRequirementExpression::And(
                Box::new(CodeRequirementExpression::AnchorAppleGeneric),
                Box::new(CodeRequirementExpression::CertificateGeneric(
                    1,
                    CertificateAuthorityExtension::DeveloperId.as_oid(),
                    CodeRequirementMatchExpression::Exists,
                )),
            )),
            Box::new(CodeRequirementExpression::Or(
                Box::new(CodeRequirementExpression::CertificateGeneric(
                    0,
                    CodeSigningCertificateExtension::DeveloperIdInstaller.as_oid(),
                    CodeRequirementMatchExpression::Exists,
                )),
                Box::new(CodeRequirementExpression::CertificateGeneric(
                    0,
                    CodeSigningCertificateExtension::DeveloperIdApplication.as_oid(),
                    CodeRequirementMatchExpression::Exists,
                )),
            )),
        )),
        Box::new(CodeRequirementExpression::Notarized),
    )
});

/// Defines well-known execution policies for signed code.
///
/// Instances can be obtained from a human-readable string for convenience. Those
/// strings are:
///
/// * `developer-id-signed`
/// * `developer-id-notarized-executable`
/// * `developer-id-notarized-installer`
#[allow(clippy::enum_variant_names)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, clap::ValueEnum)]
pub enum ExecutionPolicy {
    /// Code is signed by a certificate authorized for signing Mac applications or
    /// installers and that certificate was issued by
    /// [crate::apple_certificates::KnownCertificate::DeveloperIdG1] or
    /// [crate::apple_certificates::KnownCertificate::DeveloperIdG2].
    ///
    /// This is the policy that applies when you get a `Developer ID Application` or
    /// `Developer ID Installer` certificate from Apple.
    DeveloperIdSigned,

    /// Like [Self::DeveloperIdSigned] but only applies to executables (not installers)
    /// and the executable must be notarized.
    ///
    /// If you notarize an individual executable, you effectively convert the
    /// [Self::DeveloperIdSigned] policy into this variant.
    DeveloperIdNotarizedExecutable,

    /// Like [Self::DeveloperIdSigned] but only applies to installers (not executables)
    /// and the installer must be notarized.
    ///
    /// If you notarize an individual installer, you effectively convert the
    /// [Self::DeveloperIdSigned] policy into this variant.
    DeveloperIdNotarizedInstaller,
}

impl Deref for ExecutionPolicy {
    type Target = CodeRequirementExpression<'static>;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::DeveloperIdSigned => POLICY_MAC_DEVELOPER_ID.deref(),
            Self::DeveloperIdNotarizedExecutable => POLICY_NOTARIZED_EXECUTABLE.deref(),
            Self::DeveloperIdNotarizedInstaller => POLICY_NOTARIZED_INSTALLER.deref(),
        }
    }
}

impl TryFrom<&str> for ExecutionPolicy {
    type Error = AppleCodesignError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s {
            "developer-id-signed" => Ok(Self::DeveloperIdSigned),
            "developer-id-notarized-executable" => Ok(Self::DeveloperIdNotarizedExecutable),
            "developer-id-notarized-installer" => Ok(Self::DeveloperIdNotarizedInstaller),
            _ => Err(AppleCodesignError::UnknownPolicy(s.to_string())),
        }
    }
}

/// Derive a designated requirements expression given a code signing certificate.
///
/// The default expression is derived from properties of the signing
/// certificate. If it is an Apple signed certificate, extensions on the
/// issuer CA denote which expression to use.
///
/// For non-Apple signed certificates, the expression self-references the
/// issuing certificate in the same Organization as the signing certificate.
pub fn derive_designated_requirements(
    signing_cert: &CapturedX509Certificate,
    chain: &[CapturedX509Certificate],
    identifier: Option<String>,
) -> Result<CodeRequirementExpression<'static>, AppleCodesignError> {
    let expr = if signing_cert.chains_to_apple_root_ca() {
        let apple_chain = signing_cert.apple_issuing_chain();

        assert!(
            !apple_chain.is_empty(),
            "we should be able to resolve the Apple CA chain if chains_to_apple_root_ca() is true"
        );

        let first = apple_chain[0];

        if first
            .apple_ca_extensions()
            .into_iter()
            .any(|ext| ext == CertificateAuthorityExtension::AppleWorldwideDeveloperRelations)
        {
            let cn = signing_cert.subject_common_name().ok_or_else(|| {
                AppleCodesignError::PolicyFormulationError(
                    "certificate common name not available".to_string(),
                )
            })?;
            worldwide_developer_relations_signed_expression(cn)
        } else if first
            .apple_ca_extensions()
            .into_iter()
            .any(|ext| ext == CertificateAuthorityExtension::DeveloperId)
        {
            let team_id = signing_cert.apple_team_id().ok_or_else(|| {
                AppleCodesignError::PolicyFormulationError(
                    "could not find team identifier in signing certificate".to_string(),
                )
            })?;

            developer_id_signed_expression(team_id)
        } else {
            CodeRequirementExpression::AnchorApple
        }
    } else {
        // Ensure the chain is sorted.
        let chain = signing_cert
            .resolve_signing_chain(chain.iter())
            .into_iter()
            .cloned()
            .collect::<Vec<_>>();

        non_apple_signed_expression(signing_cert, &chain)?
    };

    // Chain the expression with the identifier, if given.
    Ok(if let Some(identifier) = identifier {
        CodeRequirementExpression::And(
            Box::new(CodeRequirementExpression::Identifier(identifier.into())),
            Box::new(expr),
        )
    } else {
        expr
    })
}

/// Derive a code requirements expression for a Developer ID issued certificate.
///
/// The expression is pinned to the team ID / organization unit of the signing
/// certificate, which must be passed in.
pub fn developer_id_signed_expression(
    team_id: impl ToString,
) -> CodeRequirementExpression<'static> {
    CodeRequirementExpression::And(
        // Chains to Apple root CA.
        Box::new(CodeRequirementExpression::AnchorAppleGeneric),
        Box::new(CodeRequirementExpression::And(
            // Certificate issued by CA with Developer ID extension.
            Box::new(CodeRequirementExpression::CertificateGeneric(
                1,
                CertificateAuthorityExtension::DeveloperId.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
            Box::new(CodeRequirementExpression::And(
                // A certificate entrusted with Developer ID Application signing rights.
                Box::new(CodeRequirementExpression::CertificateGeneric(
                    0,
                    CodeSigningCertificateExtension::DeveloperIdApplication.as_oid(),
                    CodeRequirementMatchExpression::Exists,
                )),
                // Signed by this team ID.
                Box::new(CodeRequirementExpression::CertificateField(
                    0,
                    "subject.OU".to_string().into(),
                    CodeRequirementMatchExpression::Equal(team_id.to_string().into()),
                )),
            )),
        )),
    )
}

/// Derive the requirements expression for a cert signed by the Worldwide Developer Relations CA.
///
/// The expression is pinned to the Common Name (CN) field of the signing
/// certificate, which must be passed in.
pub fn worldwide_developer_relations_signed_expression(
    leaf_common_name: impl ToString,
) -> CodeRequirementExpression<'static> {
    // anchor apple generic and
    CodeRequirementExpression::And(
        Box::new(CodeRequirementExpression::AnchorAppleGeneric),
        // leaf[subject.CN] = <leaf subject> and
        Box::new(CodeRequirementExpression::And(
            Box::new(CodeRequirementExpression::CertificateField(
                0,
                "subject.CN".to_string().into(),
                CodeRequirementMatchExpression::Equal(leaf_common_name.to_string().into()),
            )),
            // certificate 1[field.1.2.840.113635.100.6.2.1] exists
            Box::new(CodeRequirementExpression::CertificateGeneric(
                1,
                CertificateAuthorityExtension::AppleWorldwideDeveloperRelations.as_oid(),
                CodeRequirementMatchExpression::Exists,
            )),
        )),
    )
}

/// Derive the requirements expression for non Apple signed certificates.
///
/// The signing certificate should be the first certificate in the passed chain.
/// The chain should be sorted so the root CA is last.
pub fn non_apple_signed_expression(
    signing_cert: &CapturedX509Certificate,
    chain: &[CapturedX509Certificate],
) -> Result<CodeRequirementExpression<'static>, AppleCodesignError> {
    let leaf_raw: &x509_certificate::rfc5280::Certificate = signing_cert.as_ref();

    let leaf_organization = leaf_raw
        .tbs_certificate
        .subject
        .iter_organization()
        .next()
        .and_then(|o| o.to_string().ok());

    // We pin the last certificate in the signing chain having the same
    // organization as the signing certificate.

    let mut pin_index = 0i32;

    if let Some(leaf_organization) = leaf_organization {
        for cert in chain.iter() {
            let ca_raw: &x509_certificate::rfc5280::Certificate = cert.as_ref();

            if let Some(org) = ca_raw
                .tbs_certificate
                .subject
                .iter_organization()
                .next()
                .and_then(|o| o.to_string().ok())
            {
                if org != leaf_organization {
                    break;
                }

                pin_index += 1;
            }
        }
    }

    // If the entire chain is signed by the same Organization, use the
    // special cert index value to pin the root cert.
    if pin_index as usize == chain.len() {
        pin_index = -1;
    }

    let digest = signing_cert
        .fingerprint(x509_certificate::DigestAlgorithm::Sha1)?
        .as_ref()
        .to_vec();

    Ok(CodeRequirementExpression::AnchorCertificateHash(
        pin_index,
        digest.into(),
    ))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_policies() {
        ExecutionPolicy::DeveloperIdSigned.to_bytes().unwrap();
        ExecutionPolicy::DeveloperIdNotarizedExecutable
            .to_bytes()
            .unwrap();
        ExecutionPolicy::DeveloperIdNotarizedInstaller
            .to_bytes()
            .unwrap();
    }

    const APPLE_SIGNED_CN: &str = "Apple Development: Gregory Szorc (DD5YMVP48D)";
    const DEVELOPER_ID_TEXT: &str = "(anchor apple generic) and ((certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */) and ((certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */) and (certificate leaf[subject.OU] = \"MK22MZP987\")))";
    const WWDR_TEXT: &str = "(anchor apple generic) and ((certificate leaf[subject.CN] = \"Apple Development: Gregory Szorc (DD5YMVP48D)\") and (certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */))";

    fn load_unified_pem(pem_data: &[u8]) -> CapturedX509Certificate {
        pem::parse_many(pem_data)
            .unwrap()
            .into_iter()
            .filter_map(|doc| {
                if doc.tag() == "CERTIFICATE" {
                    Some(doc.contents().to_vec())
                } else {
                    None
                }
            })
            .map(|der| CapturedX509Certificate::from_der(der).unwrap())
            .next()
            .unwrap()
    }

    #[test]
    fn developer_id_requirements_derive() {
        let der = include_bytes!("testdata/apple-signed-developer-id-application.cer");
        let cert = CapturedX509Certificate::from_der(der.to_vec()).unwrap();

        assert_eq!(
            developer_id_signed_expression(cert.apple_team_id().unwrap()).to_string(),
            DEVELOPER_ID_TEXT
        );
        assert_eq!(
            derive_designated_requirements(&cert, &[], None)
                .unwrap()
                .to_string(),
            DEVELOPER_ID_TEXT
        );
    }

    #[test]
    fn worldwide_developer_relations() {
        assert_eq!(
            worldwide_developer_relations_signed_expression(APPLE_SIGNED_CN).to_string(),
            WWDR_TEXT
        );
    }

    #[test]
    fn non_apple_signed() {
        let self_signed = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-apple-development.pem"
        ));

        assert_eq!(
            non_apple_signed_expression(&self_signed, &[])
                .unwrap()
                .to_string(),
            "certificate root = H\"e1c7216e46533c923b7cfc94e86c7043790b96e9\""
        );

        // Now try with an Apple chain. The function doesn't care that it is
        // operating on a non-Apple chain.
        let apple_development = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-apple-development.cer").to_vec(),
        )
        .unwrap();
        let chain = apple_development.apple_root_certificate_chain().unwrap();

        assert_eq!(
            non_apple_signed_expression(&apple_development, &chain[1..])
                .unwrap()
                .to_string(),
            "certificate leaf = H\"5eeadb4befce055e06b4239ad4c5f0d1bfd6af8f\""
        );
    }

    #[test]
    fn apple_signed_auto_derive() {
        let apple_development = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-apple-development.cer").to_vec(),
        )
        .unwrap();
        let apple_distribution = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-apple-distribution.cer").to_vec(),
        )
        .unwrap();
        let developer_id_application = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-developer-id-application.cer").to_vec(),
        )
        .unwrap();
        let developer_id_installer = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-developer-id-installer.cer").to_vec(),
        )
        .unwrap();
        let mac_installer_distribution = CapturedX509Certificate::from_der(
            include_bytes!("testdata/apple-signed-3rd-party-mac.cer").to_vec(),
        )
        .unwrap();

        assert_eq!(
            derive_designated_requirements(&apple_development, &[], None)
                .unwrap()
                .to_string(),
            WWDR_TEXT
        );
        assert_eq!(
            derive_designated_requirements(&apple_distribution, &[], None)
                .unwrap()
                .to_string(),
            worldwide_developer_relations_signed_expression(
                "Apple Distribution: Gregory Szorc (MK22MZP987)"
            )
            .to_string()
        );
        assert_eq!(
            derive_designated_requirements(&developer_id_application, &[], None)
                .unwrap()
                .to_string(),
            DEVELOPER_ID_TEXT
        );
        assert_eq!(
            derive_designated_requirements(&developer_id_installer, &[], None)
                .unwrap()
                .to_string(),
            developer_id_signed_expression("MK22MZP987").to_string()
        );
        assert_eq!(
            derive_designated_requirements(&mac_installer_distribution, &[], None)
                .unwrap()
                .to_string(),
            worldwide_developer_relations_signed_expression(
                "3rd Party Mac Developer Installer: Gregory Szorc (MK22MZP987)"
            )
            .to_string()
        );
    }

    #[test]
    fn self_signed_auto_derive() {
        let apple_development = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-apple-development.pem"
        ));
        let apple_distribution = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-apple-distribution.pem"
        ));
        let developer_id_application = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-developer-id-application.pem"
        ));
        let developer_id_installer = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-developer-id-installer.pem"
        ));
        let mac_installer_distribution = load_unified_pem(include_bytes!(
            "testdata/self-signed-rsa-mac-installer-distribution.pem"
        ));

        let derive = |cert| -> String {
            derive_designated_requirements(cert, &[], None)
                .unwrap()
                .to_string()
        };

        assert_eq!(
            derive(&apple_development),
            "certificate root = H\"e1c7216e46533c923b7cfc94e86c7043790b96e9\""
        );
        assert_eq!(
            derive(&apple_distribution),
            "certificate root = H\"0383efdf909250708bf2de4d43753836ccb3d608\""
        );
        assert_eq!(
            derive(&developer_id_application),
            "certificate root = H\"3acf1d302fe3a4bba06a3c16aadc908045bc9162\""
        );
        assert_eq!(
            derive(&developer_id_installer),
            "certificate root = H\"5c1314a89e5a486ac7b1da86b38e08777adca4af\""
        );
        assert_eq!(
            derive(&mac_installer_distribution),
            "certificate root = H\"58e39fe0fca55e7af4ca00027bc7c59e566e960a\""
        );
    }
}
