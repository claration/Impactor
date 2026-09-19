// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Functionality related to "code resources," external resources captured in signatures.
//!
//! Bundles can contain a `_CodeSignature/CodeResources` XML plist file
//! denoting signatures for resources not in the binary. The signature data
//! in the binary can record the digest of this file so integrity is transitively
//! verified.
//!
//! We've implemented our own (de)serialization code in this module because
//! the default derived Deserialize provided by the `plist` crate doesn't
//! handle enums correctly. We attempted to implement our own `Deserialize`
//! and `Visitor` traits to get things to parse, but we couldn't make it work.
//! We gave up and decided to just coerce the [plist::Value] instances instead.

use {
    crate::{
        bundle_signing::{BundleSigningContext, SignedMachOInfo},
        cryptography::{DigestType, MultiDigest},
        error::AppleCodesignError,
    },
    apple_bundles::DirectoryBundle,
    log::{debug, error, info, warn},
    plist::{Dictionary, Value},
    std::{
        cmp::Ordering,
        collections::{BTreeMap, BTreeSet},
        io::Write,
        path::Path,
    },
};

#[derive(Clone, PartialEq)]
enum FilesValue {
    Required(Vec<u8>),
    Optional(Vec<u8>),
}

impl std::fmt::Debug for FilesValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required(digest) => f
                .debug_struct("FilesValue")
                .field("required", &true)
                .field("digest", &hex::encode(digest))
                .finish(),
            Self::Optional(digest) => f
                .debug_struct("FilesValue")
                .field("required", &false)
                .field("digest", &hex::encode(digest))
                .finish(),
        }
    }
}

impl std::fmt::Display for FilesValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Required(digest) => {
                f.write_fmt(format_args!("{} (required)", hex::encode(digest)))
            }
            Self::Optional(digest) => {
                f.write_fmt(format_args!("{} (optional)", hex::encode(digest)))
            }
        }
    }
}

impl TryFrom<&Value> for FilesValue {
    type Error = AppleCodesignError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        match v {
            Value::Data(digest) => Ok(Self::Required(digest.to_vec())),
            Value::Dictionary(dict) => {
                let mut digest = None;
                let mut optional = None;

                for (key, value) in dict.iter() {
                    match key.as_str() {
                        "hash" => {
                            let data = value.as_data().ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "expected <data> for files <dict> entry, got {value:?}"
                                ))
                            })?;

                            digest = Some(data.to_vec());
                        }
                        "optional" => {
                            let v = value.as_boolean().ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "expected boolean for optional key, got {value:?}"
                                ))
                            })?;

                            optional = Some(v);
                        }
                        key => {
                            return Err(AppleCodesignError::ResourcesPlistParse(format!(
                                "unexpected key in files dict: {key}"
                            )));
                        }
                    }
                }

                match (digest, optional) {
                    (Some(digest), Some(true)) => Ok(Self::Optional(digest)),
                    (Some(digest), Some(false)) => Ok(Self::Required(digest)),
                    _ => Err(AppleCodesignError::ResourcesPlistParse(
                        "missing hash or optional key".to_string(),
                    )),
                }
            }
            _ => Err(AppleCodesignError::ResourcesPlistParse(format!(
                "bad value in files <dict>; expected <data> or <dict>, got {v:?}"
            ))),
        }
    }
}

impl From<&FilesValue> for Value {
    fn from(v: &FilesValue) -> Self {
        match v {
            FilesValue::Required(digest) => Self::Data(digest.to_vec()),
            FilesValue::Optional(digest) => {
                let mut dict = Dictionary::new();
                dict.insert("hash".to_string(), Value::Data(digest.to_vec()));
                dict.insert("optional".to_string(), Value::Boolean(true));

                Self::Dictionary(dict)
            }
        }
    }
}

#[derive(Clone, PartialEq)]
struct Files2Value {
    cdhash: Option<Vec<u8>>,
    hash: Option<Vec<u8>>,
    hash2: Option<Vec<u8>>,
    optional: Option<bool>,
    requirement: Option<String>,
    symlink: Option<String>,
}

impl std::fmt::Debug for Files2Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Files2Value")
            .field(
                "cdhash",
                &format_args!("{:?}", self.cdhash.as_ref().map(hex::encode)),
            )
            .field(
                "hash",
                &format_args!("{:?}", self.hash.as_ref().map(hex::encode)),
            )
            .field(
                "hash2",
                &format_args!("{:?}", self.hash2.as_ref().map(hex::encode)),
            )
            .field("optional", &format_args!("{:?}", self.optional))
            .field("requirement", &format_args!("{:?}", self.requirement))
            .field("symlink", &format_args!("{:?}", self.symlink))
            .finish()
    }
}

impl TryFrom<&Value> for Files2Value {
    type Error = AppleCodesignError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let dict = v.as_dictionary().ok_or_else(|| {
            AppleCodesignError::ResourcesPlistParse("files2 value should be a dict".to_string())
        })?;

        let mut hash = None;
        let mut hash2 = None;
        let mut cdhash = None;
        let mut optional = None;
        let mut requirement = None;
        let mut symlink = None;

        for (key, value) in dict.iter() {
            match key.as_str() {
                "cdhash" => {
                    let data = value.as_data().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected <data> for files2 cdhash entry, got {value:?}"
                        ))
                    })?;

                    cdhash = Some(data.to_vec());
                }
                "hash" => {
                    let data = value.as_data().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected <data> for files2 hash entry, got {value:?}"
                        ))
                    })?;

                    hash = Some(data.to_vec());
                }
                "hash2" => {
                    let data = value.as_data().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected <data> for files2 hash2 entry, got {value:?}"
                        ))
                    })?;

                    hash2 = Some(data.to_vec());
                }
                "optional" => {
                    let v = value.as_boolean().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected bool for optional key, got {value:?}"
                        ))
                    })?;

                    optional = Some(v);
                }
                "requirement" => {
                    let v = value.as_string().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected string for requirement key, got {value:?}"
                        ))
                    })?;

                    requirement = Some(v.to_string());
                }
                "symlink" => {
                    symlink = Some(
                        value
                            .as_string()
                            .ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "expected string for symlink key, got {value:?}"
                                ))
                            })?
                            .to_string(),
                    );
                }
                key => {
                    return Err(AppleCodesignError::ResourcesPlistParse(format!(
                        "unexpected key in files2 dict entry: {key}"
                    )));
                }
            }
        }

        Ok(Self {
            cdhash,
            hash,
            hash2,
            optional,
            requirement,
            symlink,
        })
    }
}

impl From<&Files2Value> for Value {
    fn from(v: &Files2Value) -> Self {
        let mut dict = Dictionary::new();

        if let Some(cdhash) = &v.cdhash {
            dict.insert("cdhash".to_string(), Value::Data(cdhash.to_vec()));
        }

        if let Some(hash) = &v.hash {
            dict.insert("hash".to_string(), Value::Data(hash.to_vec()));
        }

        if let Some(hash2) = &v.hash2 {
            dict.insert("hash2".to_string(), Value::Data(hash2.to_vec()));
        }

        if let Some(optional) = &v.optional {
            dict.insert("optional".to_string(), Value::Boolean(*optional));
        }

        if let Some(requirement) = &v.requirement {
            dict.insert(
                "requirement".to_string(),
                Value::String(requirement.to_string()),
            );
        }

        if let Some(symlink) = &v.symlink {
            dict.insert("symlink".to_string(), Value::String(symlink.to_string()));
        }

        Value::Dictionary(dict)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct RulesValue {
    omit: bool,
    required: bool,
    weight: Option<f64>,
}

impl TryFrom<&Value> for RulesValue {
    type Error = AppleCodesignError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        match v {
            Value::Boolean(true) => Ok(Self {
                omit: false,
                required: true,
                weight: None,
            }),
            Value::Dictionary(dict) => {
                let mut omit = None;
                let mut optional = None;
                let mut weight = None;

                for (key, value) in dict {
                    match key.as_str() {
                        "omit" => {
                            omit = Some(value.as_boolean().ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "rules omit key value not a boolean; got {value:?}"
                                ))
                            })?);
                        }
                        "optional" => {
                            optional = Some(value.as_boolean().ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "rules optional key value not a boolean, got {value:?}"
                                ))
                            })?);
                        }
                        "weight" => {
                            weight = Some(value.as_real().ok_or_else(|| {
                                AppleCodesignError::ResourcesPlistParse(format!(
                                    "rules weight key value not a real, got {value:?}"
                                ))
                            })?);
                        }
                        key => {
                            return Err(AppleCodesignError::ResourcesPlistParse(format!(
                                "extra key in rules dict: {key}"
                            )));
                        }
                    }
                }

                Ok(Self {
                    omit: omit.unwrap_or(false),
                    required: !optional.unwrap_or(false),
                    weight,
                })
            }
            _ => Err(AppleCodesignError::ResourcesPlistParse(
                "invalid value for rules entry".to_string(),
            )),
        }
    }
}

impl From<&RulesValue> for Value {
    fn from(v: &RulesValue) -> Self {
        if v.required && !v.omit && v.weight.is_none() {
            Value::Boolean(true)
        } else {
            let mut dict = Dictionary::new();

            if v.omit {
                dict.insert("omit".to_string(), Value::Boolean(true));
            }
            if !v.required {
                dict.insert("optional".to_string(), Value::Boolean(true));
            }

            if let Some(weight) = v.weight {
                dict.insert("weight".to_string(), Value::Real(weight));
            }

            Value::Dictionary(dict)
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Rules2Value {
    nested: Option<bool>,
    omit: Option<bool>,
    optional: Option<bool>,
    weight: Option<f64>,
}

impl TryFrom<&Value> for Rules2Value {
    type Error = AppleCodesignError;

    fn try_from(v: &Value) -> Result<Self, Self::Error> {
        let dict = v.as_dictionary().ok_or_else(|| {
            AppleCodesignError::ResourcesPlistParse("rules2 value should be a dict".to_string())
        })?;

        let mut nested = None;
        let mut omit = None;
        let mut optional = None;
        let mut weight = None;

        for (key, value) in dict.iter() {
            match key.as_str() {
                "nested" => {
                    nested = Some(value.as_boolean().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected bool for rules2 nested key, got {value:?}"
                        ))
                    })?);
                }
                "omit" => {
                    omit = Some(value.as_boolean().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected bool for rules2 omit key, got {value:?}"
                        ))
                    })?);
                }
                "optional" => {
                    optional = Some(value.as_boolean().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected bool for rules2 optional key, got {value:?}"
                        ))
                    })?);
                }
                "weight" => {
                    weight = Some(value.as_real().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expected real for rules2 weight key, got {value:?}"
                        ))
                    })?);
                }
                key => {
                    return Err(AppleCodesignError::ResourcesPlistParse(format!(
                        "unexpected key in rules dict entry: {key}"
                    )));
                }
            }
        }

        Ok(Self {
            nested,
            omit,
            optional,
            weight,
        })
    }
}

impl From<&Rules2Value> for Value {
    fn from(v: &Rules2Value) -> Self {
        let mut dict = Dictionary::new();

        if let Some(true) = v.nested {
            dict.insert("nested".to_string(), Value::Boolean(true));
        }

        if let Some(true) = v.omit {
            dict.insert("omit".to_string(), Value::Boolean(true));
        }

        if let Some(true) = v.optional {
            dict.insert("optional".to_string(), Value::Boolean(true));
        }

        if let Some(weight) = v.weight {
            dict.insert("weight".to_string(), Value::Real(weight));
        }

        if dict.is_empty() {
            Value::Boolean(true)
        } else {
            Value::Dictionary(dict)
        }
    }
}

/// Represents an abstract rule in a `CodeResources` XML plist.
///
/// This type represents both `<rules>` and `<rules2>` entries. It contains a
/// superset of all fields for these entries.
#[derive(Clone, Debug)]
pub struct CodeResourcesRule {
    /// The rule pattern.
    ///
    /// The `<key>` in the `<rules>` or `<rules2>` dict.
    pub pattern: String,

    /// Matched paths are excluded from processing completely.
    ///
    /// If any rule with this flag matches a path, the path is excluded.
    pub exclude: bool,

    /// The matched path is a signable entity.
    ///
    /// The path should be signed before sealing. And its seal may be
    /// stored specially.
    pub nested: bool,

    /// Whether to omit the path from sealing.
    ///
    /// Paths matching this rule can exist in a bundle. But their content
    /// isn't captured in the `CodeResources` file.
    pub omit: bool,

    /// Unknown. Best guess is whether the file's presence is optional.
    pub optional: bool,

    /// Weighting to apply to the rule.
    pub weight: Option<u32>,

    re: regex::Regex,
}

impl PartialEq for CodeResourcesRule {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
            && self.exclude == other.exclude
            && self.nested == other.nested
            && self.omit == other.omit
            && self.optional == other.optional
            && self.weight == other.weight
    }
}

impl Eq for CodeResourcesRule {}

impl PartialOrd for CodeResourcesRule {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CodeResourcesRule {
    fn cmp(&self, other: &Self) -> Ordering {
        // Default weight is 1 if not specified.
        let our_weight = self.weight.unwrap_or(1);
        let their_weight = other.weight.unwrap_or(1);

        // Exclusion rules always take priority over inclusion rules.
        // The smaller the weight, the less important it is.
        match (self.exclude, other.exclude) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => their_weight.cmp(&our_weight),
        }
    }
}

impl CodeResourcesRule {
    pub fn new(pattern: impl ToString) -> Result<Self, AppleCodesignError> {
        Ok(Self {
            pattern: pattern.to_string(),
            exclude: false,
            nested: false,
            omit: false,
            optional: false,
            weight: None,
            re: regex::Regex::new(&pattern.to_string())
                .map_err(|e| AppleCodesignError::ResourcesBadRegex(pattern.to_string(), e))?,
        })
    }

    /// Mark this as an exclusion rule.
    ///
    /// Exclusion rules are internal to the builder and not materialized in the
    /// `CodeResources` file.
    #[must_use]
    pub fn exclude(mut self) -> Self {
        self.exclude = true;
        self
    }

    /// Mark the rule as nested.
    #[must_use]
    pub fn nested(mut self) -> Self {
        self.nested = true;
        self
    }

    /// Set the omit field.
    #[must_use]
    pub fn omit(mut self) -> Self {
        self.omit = true;
        self
    }

    /// Mark the files matched by this rule are optional.
    #[must_use]
    pub fn optional(mut self) -> Self {
        self.optional = true;
        self
    }

    /// Set the weight of this rule.
    #[must_use]
    pub fn weight(mut self, v: u32) -> Self {
        self.weight = Some(v);
        self
    }
}

/// Which files section we are operating on and how to digest.
#[derive(Clone, Copy, Debug)]
pub enum FilesFlavor {
    /// `<rules>`.
    Rules,
    /// `<rules2>`.
    Rules2,
    /// `<rules2>` and also include the SHA-1 digest.
    Rules2WithSha1,
}

/// Represents a `_CodeSignature/CodeResources` XML plist.
///
/// This file/type represents a collection of file-based resources whose
/// content is digested and captured in this file.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CodeResources {
    files: BTreeMap<String, FilesValue>,
    files2: BTreeMap<String, Files2Value>,
    rules: BTreeMap<String, RulesValue>,
    rules2: BTreeMap<String, Rules2Value>,
}

impl CodeResources {
    /// Construct an instance by parsing an XML plist.
    pub fn from_xml(xml: &[u8]) -> Result<Self, AppleCodesignError> {
        let plist = Value::from_reader_xml(xml).map_err(AppleCodesignError::ResourcesPlist)?;

        let dict = plist.into_dictionary().ok_or_else(|| {
            AppleCodesignError::ResourcesPlistParse(
                "plist root element should be a <dict>".to_string(),
            )
        })?;

        let mut files = BTreeMap::new();
        let mut files2 = BTreeMap::new();
        let mut rules = BTreeMap::new();
        let mut rules2 = BTreeMap::new();

        for (key, value) in dict.iter() {
            match key.as_ref() {
                "files" => {
                    let dict = value.as_dictionary().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expecting files to be a dict, got {value:?}"
                        ))
                    })?;

                    for (key, value) in dict {
                        files.insert(key.to_string(), FilesValue::try_from(value)?);
                    }
                }
                "files2" => {
                    let dict = value.as_dictionary().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expecting files2 to be a dict, got {value:?}"
                        ))
                    })?;

                    for (key, value) in dict {
                        files2.insert(key.to_string(), Files2Value::try_from(value)?);
                    }
                }
                "rules" => {
                    let dict = value.as_dictionary().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expecting rules to be a dict, got {value:?}"
                        ))
                    })?;

                    for (key, value) in dict {
                        rules.insert(key.to_string(), RulesValue::try_from(value)?);
                    }
                }
                "rules2" => {
                    let dict = value.as_dictionary().ok_or_else(|| {
                        AppleCodesignError::ResourcesPlistParse(format!(
                            "expecting rules2 to be a dict, got {value:?}"
                        ))
                    })?;

                    for (key, value) in dict {
                        rules2.insert(key.to_string(), Rules2Value::try_from(value)?);
                    }
                }
                key => {
                    return Err(AppleCodesignError::ResourcesPlistParse(format!(
                        "unexpected key in root dict: {key}"
                    )));
                }
            }
        }

        Ok(Self {
            files,
            files2,
            rules,
            rules2,
        })
    }

    /// Serialize an instance to XML.
    pub fn to_writer_xml(&self, mut writer: impl Write) -> Result<(), AppleCodesignError> {
        let value = Value::from(self);

        // Ideally we'd write direct to the output. However, Apple's XML writer doesn't
        // emit a space for empty elements. e.g. we do `<true />` and Apple does `<true/>`.
        // In addition, our writer doesn't emit a trailing newline. To make it easier to
        // diff generated files with the canonical output, we normalize to Apple's format.
        let mut data = Vec::<u8>::new();
        value
            .to_writer_xml(&mut data)
            .map_err(AppleCodesignError::ResourcesPlist)?;

        let data = String::from_utf8(data).expect("XML should be valid UTF-8");
        let data = data.replace("<dict />", "<dict/>");
        let data = data.replace("<true />", "<true/>");
        let data = data.replace("&quot;", "\"");

        writer.write_all(data.as_bytes())?;
        writer.write_all(b"\n")?;

        Ok(())
    }

    /// Add a rule to this instance in the `<rules>` section.
    pub fn add_rule(&mut self, rule: CodeResourcesRule) {
        self.rules.insert(
            rule.pattern,
            RulesValue {
                omit: rule.omit,
                required: !rule.optional,
                weight: rule.weight.map(|x| x as f64),
            },
        );
    }

    /// Add a rule to this instance in the `<rules2>` section.
    pub fn add_rule2(&mut self, rule: CodeResourcesRule) {
        self.rules2.insert(
            rule.pattern,
            Rules2Value {
                nested: if rule.nested { Some(true) } else { None },
                omit: if rule.omit { Some(true) } else { None },
                optional: if rule.optional { Some(true) } else { None },
                weight: rule.weight.map(|x| x as f64),
            },
        );
    }

    /// Seal a regular file.
    ///
    /// This will digest the content specified and record that digest in the files or
    /// files2 list.
    ///
    /// To seal a symlink, call [CodeResources::seal_symlink] instead. If the file
    /// is a Mach-O file, call [CodeResources::seal_macho] instead.
    pub fn seal_regular_file(
        &mut self,
        files_flavor: FilesFlavor,
        path: impl ToString,
        digests: MultiDigest,
        optional: bool,
    ) -> Result<(), AppleCodesignError> {
        match files_flavor {
            FilesFlavor::Rules => {
                self.files.insert(
                    path.to_string(),
                    if optional {
                        FilesValue::Optional(digests.sha1.to_vec())
                    } else {
                        FilesValue::Required(digests.sha1.to_vec())
                    },
                );

                Ok(())
            }
            FilesFlavor::Rules2 => {
                let hash2 = Some(digests.sha256.to_vec());

                self.files2.insert(
                    path.to_string(),
                    Files2Value {
                        cdhash: None,
                        hash: None,
                        hash2,
                        optional: if optional { Some(true) } else { None },
                        requirement: None,
                        symlink: None,
                    },
                );

                Ok(())
            }
            FilesFlavor::Rules2WithSha1 => {
                let hash = Some(digests.sha1.to_vec());
                let hash2 = Some(digests.sha256.to_vec());

                self.files2.insert(
                    path.to_string(),
                    Files2Value {
                        cdhash: None,
                        hash,
                        hash2,
                        optional: if optional { Some(true) } else { None },
                        requirement: None,
                        symlink: None,
                    },
                );

                Ok(())
            }
        }
    }

    /// Seal a symlink file.
    ///
    /// `path` is the path of the symlink and `target` is the path it points to.
    pub fn seal_symlink(&mut self, path: impl ToString, target: impl ToString) {
        // Version 1 doesn't support sealing symlinks.
        self.files2.insert(
            path.to_string(),
            Files2Value {
                cdhash: None,
                hash: None,
                hash2: None,
                optional: None,
                requirement: None,
                symlink: Some(target.to_string()),
            },
        );
    }

    /// Record metadata of a previously signed Mach-O binary.
    ///
    /// If sealing a fat/universal binary, pass in metadata for the first Mach-O within in.
    pub fn seal_macho(
        &mut self,
        path: impl ToString,
        info: &SignedMachOInfo,
        optional: bool,
    ) -> Result<(), AppleCodesignError> {
        self.files2.insert(
            path.to_string(),
            Files2Value {
                cdhash: Some(DigestType::Sha256Truncated.digest_data(&info.code_directory_blob)?),
                hash: None,
                hash2: None,
                optional: if optional { Some(true) } else { None },
                requirement: info.designated_code_requirement.clone(),
                symlink: None,
            },
        );

        Ok(())
    }
}

impl From<&CodeResources> for Value {
    fn from(cr: &CodeResources) -> Self {
        let mut dict = Dictionary::new();

        dict.insert(
            "files".to_string(),
            Value::Dictionary(
                cr.files
                    .iter()
                    .map(|(key, value)| (key.to_string(), Value::from(value)))
                    .collect::<Dictionary>(),
            ),
        );

        dict.insert(
            "files2".to_string(),
            Value::Dictionary(
                cr.files2
                    .iter()
                    .map(|(key, value)| (key.to_string(), Value::from(value)))
                    .collect::<Dictionary>(),
            ),
        );

        if !cr.rules.is_empty() {
            dict.insert(
                "rules".to_string(),
                Value::Dictionary(
                    cr.rules
                        .iter()
                        .map(|(key, value)| (key.to_string(), Value::from(value)))
                        .collect::<Dictionary>(),
                ),
            );
        }

        if !cr.rules2.is_empty() {
            dict.insert(
                "rules2".to_string(),
                Value::Dictionary(
                    cr.rules2
                        .iter()
                        .map(|(key, value)| (key.to_string(), Value::from(value)))
                        .collect::<Dictionary>(),
                ),
            );
        }

        Value::Dictionary(dict)
    }
}

/// Convert a relative filesystem path to its `CodeResources` normalized form.
pub fn normalized_resources_path(path: impl AsRef<Path>) -> String {
    // Always use UNIX style directory separators.
    let path = path.as_ref().to_string_lossy().replace('\\', "/");

    // The Contents/ prefix is also removed for pattern matching and references in the
    // resources file.
    let path = path.strip_prefix("Contents/").unwrap_or(&path).to_string();

    path
}

/// Find the first rule matching a given path.
///
/// Internally, rules are sorted by decreasing priority, with exclusion
/// rules having highest priority. So the first pattern that matches is
/// rule we use.
///
/// Pattern matches are always against the normalized filename. (e.g.
/// `Contents/` is stripped.)
fn find_rule(rules: &[CodeResourcesRule], path: impl AsRef<Path>) -> Option<CodeResourcesRule> {
    let path = normalized_resources_path(path);
    rules.iter().find(|rule| rule.re.is_match(&path)).cloned()
}

/// Interface for constructing a `CodeResources` instance.
///
/// This type is used during bundle signing to construct a `CodeResources` instance.
/// It contains logic for validating a file against registered processing rules and
/// handling it accordingly.
#[derive(Clone, Debug)]
pub struct CodeResourcesBuilder {
    rules: Vec<CodeResourcesRule>,
    rules2: Vec<CodeResourcesRule>,
    resources: CodeResources,
    digests: Vec<DigestType>,
}

impl Default for CodeResourcesBuilder {
    fn default() -> Self {
        Self {
            rules: vec![],
            rules2: vec![],
            resources: CodeResources::default(),
            digests: vec![DigestType::Sha256],
        }
    }
}

impl CodeResourcesBuilder {
    /// Obtain an instance with default rules for a bundle with a `Resources/` directory.
    pub fn default_resources_rules() -> Result<Self, AppleCodesignError> {
        let mut slf = Self::default();

        slf.add_rule(CodeResourcesRule::new("^version.plist$")?);
        slf.add_rule(CodeResourcesRule::new("^Resources/")?);
        slf.add_rule(
            CodeResourcesRule::new("^Resources/.*\\.lproj/")?
                .optional()
                .weight(1000),
        );
        slf.add_rule(CodeResourcesRule::new("^Resources/Base\\.lproj/")?.weight(1010));
        slf.add_rule(
            CodeResourcesRule::new("^Resources/.*\\.lproj/locversion.plist$")?
                .omit()
                .weight(1100),
        );

        slf.add_rule2(CodeResourcesRule::new("^.*")?);
        slf.add_rule2(CodeResourcesRule::new("^[^/]+$")?.nested().weight(10));
        slf.add_rule2(CodeResourcesRule::new("^(Frameworks|SharedFrameworks|PlugIns|Plug-ins|XPCServices|Helpers|MacOS|Library/(Automator|Spotlight|LoginItems))/")?
                         .nested().weight(10));
        slf.add_rule2(CodeResourcesRule::new(".*\\.dSYM($|/)")?.weight(11));
        slf.add_rule2(
            CodeResourcesRule::new("^(.*/)?\\.DS_Store$")?
                .omit()
                .weight(2000),
        );
        slf.add_rule2(CodeResourcesRule::new("^Info\\.plist$")?.omit().weight(20));
        slf.add_rule2(CodeResourcesRule::new("^version\\.plist$")?.weight(20));
        slf.add_rule2(CodeResourcesRule::new("^embedded\\.provisionprofile$")?.weight(20));
        slf.add_rule2(CodeResourcesRule::new("^PkgInfo$")?.omit().weight(20));
        slf.add_rule2(CodeResourcesRule::new("^Resources/")?.weight(20));
        slf.add_rule2(
            CodeResourcesRule::new("^Resources/.*\\.lproj/")?
                .optional()
                .weight(1000),
        );
        slf.add_rule2(CodeResourcesRule::new("^Resources/Base\\.lproj/")?.weight(1010));
        slf.add_rule2(
            CodeResourcesRule::new("^Resources/.*\\.lproj/locversion.plist$")?
                .omit()
                .weight(1100),
        );

        Ok(slf)
    }

    /// Obtain an instance with default rules for a bundle without a `Resources/` directory.
    pub fn default_no_resources_rules() -> Result<Self, AppleCodesignError> {
        let mut slf = Self::default();

        slf.add_rule(CodeResourcesRule::new("^version.plist$")?);
        slf.add_rule(CodeResourcesRule::new("^.*")?);
        slf.add_rule(
            CodeResourcesRule::new("^.*\\.lproj/")?
                .optional()
                .weight(1000),
        );
        slf.add_rule(CodeResourcesRule::new("^Base\\.lproj/")?.weight(1010));
        slf.add_rule(
            CodeResourcesRule::new("^.*\\.lproj/locversion.plist$")?
                .omit()
                .weight(1100),
        );
        slf.add_rule2(CodeResourcesRule::new("^.*")?);
        slf.add_rule2(CodeResourcesRule::new(".*\\.dSYM($|/)")?.weight(11));
        slf.add_rule2(
            CodeResourcesRule::new("^(.*/)?\\.DS_Store$")?
                .omit()
                .weight(2000),
        );
        slf.add_rule2(CodeResourcesRule::new("^Info\\.plist$")?.omit().weight(20));
        slf.add_rule2(CodeResourcesRule::new("^version\\.plist$")?.weight(20));
        slf.add_rule2(CodeResourcesRule::new("^embedded\\.provisionprofile$")?.weight(20));
        slf.add_rule2(CodeResourcesRule::new("^PkgInfo$")?.omit().weight(20));
        slf.add_rule2(
            CodeResourcesRule::new("^.*\\.lproj/")?
                .optional()
                .weight(1000),
        );
        slf.add_rule2(CodeResourcesRule::new("^Base\\.lproj/")?.weight(1010));
        slf.add_rule2(
            CodeResourcesRule::new("^.*\\.lproj/locversion.plist$")?
                .omit()
                .weight(1100),
        );

        Ok(slf)
    }

    /// Set the digests to record in this instance.
    pub fn set_digests(&mut self, digests: impl Iterator<Item = DigestType>) {
        self.digests = digests.collect::<Vec<_>>();
    }

    /// Add a rule to this instance in the `<rules>` section.
    pub fn add_rule(&mut self, rule: CodeResourcesRule) {
        self.rules.push(rule.clone());
        self.rules.sort();
        self.resources.add_rule(rule);
    }

    /// Add a rule to this instance in the `<rules2>` section.
    pub fn add_rule2(&mut self, rule: CodeResourcesRule) {
        self.rules2.push(rule.clone());
        self.rules2.sort();
        self.resources.add_rule2(rule);
    }

    /// Add an exclusion rule to the processing rules.
    ///
    /// Exclusion rules are not added to the [CodeResources] because they are
    /// implicit and used for filesystem traversal to influence which entities
    /// are skipped.
    pub fn add_exclusion_rule(&mut self, rule: CodeResourcesRule) {
        self.rules.push(rule.clone());
        self.rules.sort();
        self.rules2.push(rule);
        self.rules2.sort();
    }

    /// Recursively seal a bundle directory.
    ///
    /// This function does the heavy lifting of walking a bundle directory
    /// and sealing the content inside.
    ///
    /// For each filesystem entry, it finds the most appropriate registered
    /// rule that applies to it. Then using that rule it takes actions.
    ///
    /// Typically, each file entity has its digest recorded/sealed.
    ///
    /// As a side-effect, files are copied/installed into the destination
    /// directory as part of sealing.
    pub fn walk_and_seal_directory(
        &mut self,
        root_bundle_path: &Path,
        bundle_root: &Path,
        context: &mut BundleSigningContext,
    ) -> Result<(), AppleCodesignError> {
        let mut skipping_rel_dirs = BTreeSet::new();

        for entry in walkdir::WalkDir::new(bundle_root).sort_by_file_name() {
            let entry = entry?;
            let path = entry.path();

            if path == bundle_root {
                continue;
            }

            let rel_path = path
                .strip_prefix(bundle_root)
                .expect("stripping path prefix should always work");
            let root_rel_path_normalized = path
                .strip_prefix(root_bundle_path)
                .expect("stripping root prefix should always work")
                .to_string_lossy()
                .replace('\\', "/");
            let rel_path_normalized = normalized_resources_path(rel_path);

            let file_name = rel_path
                .file_name()
                .expect("should have final path component")
                .to_string_lossy()
                .to_string();

            // We're excluding a parent directory. Do nothing.
            if skipping_rel_dirs.iter().any(|p| rel_path.starts_with(p)) {
                debug!("{} ignored because marked as skipped", rel_path.display());
                continue;
            }

            // Rules version 2.
            if let Some(rule) = find_rule(&self.rules2, rel_path) {
                debug!(
                    "{}:{} matches rules2 {:?}",
                    bundle_root.display(),
                    rel_path.display(),
                    rule
                );

                if entry.file_type().is_dir() {
                    if rule.nested {
                        // Only treat as a nested bundle iff it has a dot in its name.
                        if file_name.contains('.') {
                            // We assume the bundle has already been signed because that's
                            // how our bundle walker works. So all we need to do here is
                            // seal the bundle. We can skip handling all files in this
                            // directory since they've already been processed.
                            self.seal_rules2_nested_bundle(
                                path,
                                rel_path,
                                &rel_path_normalized,
                                rule.optional,
                                &context.dest_dir,
                            )?;

                            skipping_rel_dirs.insert(rel_path.to_path_buf());
                        }
                    } else if rule.exclude {
                        info!(
                            "{} marked as excluded in resource rules",
                            rel_path_normalized
                        );
                        skipping_rel_dirs.insert(rel_path.to_path_buf());
                    }

                    // No need to do anything else since we'll walk into directory
                    // to handle files.
                } else if entry.file_type().is_file() {
                    if rule.exclude {
                        debug!("{} ignoring file due to exclude rule", rel_path_normalized);
                        continue;
                    }

                    // Nested flag means the file should itself be signable.
                    if rule.nested {
                        if crate::reader::path_is_macho(path)? {
                            info!("sealing nested Mach-O binary: {}", rel_path.display());

                            self.seal_rules2_nested_macho(
                                path,
                                rel_path,
                                &rel_path_normalized,
                                &root_rel_path_normalized,
                                context,
                                rule.optional,
                            )?;
                        } else {
                            // TODO implement this?
                            // The logical intent is to sign and seal the nested entity.
                            // But if we're not a directory bundle and not a Mach-O, I'm
                            // unsure how to convey that seal. Maybe other entities like
                            // DMG and pkg installers can have their signature digest
                            // encapsulated in a cdhash?
                            error!(
                                "encountered a non Mach-O file with a nested rule: {}",
                                rel_path.display()
                            );
                            error!("we do not know how to handle this scenario; either your bundle layout is invalid or you found a bug in this program");
                            error!("if the bundle signs and verifies with Apple's tooling, consider reporting this issue");
                        }
                    } else {
                        self.seal_rules2_file(
                            path,
                            rel_path,
                            &rel_path_normalized,
                            &root_rel_path_normalized,
                            rule.omit,
                            rule.optional,
                            context,
                        )?;
                    }
                } else if entry.file_type().is_symlink() {
                    if rule.exclude {
                        info!(
                            "{} ignoring symlink due to exclude rule",
                            rel_path_normalized
                        );
                        continue;
                    }

                    self.seal_rules2_symlink(
                        path,
                        rel_path,
                        &rel_path_normalized,
                        rule.omit,
                        context,
                    )?;
                } else {
                    warn!(
                        "{} unexpected file type encountering during bundle signing",
                        rel_path_normalized
                    );
                }
            } else {
                debug!(
                    "{}:{} doesn't match any rules2 rule",
                    bundle_root.display(),
                    rel_path.display()
                );
            }

            // Now rules version 1. Only regular files can be sealed. Version
            // 1 does not support nested signatures nor symlinks.
            if let Some(rule) = find_rule(&self.rules, rel_path) {
                debug!(
                    "{}:{} matches rules rule {:?}",
                    bundle_root.display(),
                    rel_path.display(),
                    rule
                );

                if entry.file_type().is_file() {
                    if rule.exclude {
                        continue;
                    }

                    self.seal_rules1_file(path, &rel_path_normalized, rule)?;
                }
            }
        }

        Ok(())
    }

    /// Seal a nested bundle for rules version 2.
    fn seal_rules2_nested_bundle(
        &mut self,
        full_path: &Path,
        rel_path: &Path,
        rel_path_normalized: &str,
        optional: bool,
        dest_dir: &Path,
    ) -> Result<(), AppleCodesignError> {
        info!(
            "sealing nested directory as a bundle: {}",
            rel_path.display()
        );
        let bundle = DirectoryBundle::new_from_path(full_path)?;

        if let Some(nested_exe) = bundle
            .files(false)?
            .into_iter()
            .find(|f| matches!(f.is_main_executable(), Ok(true)))
        {
            let nested_exe = dest_dir.join(rel_path).join(nested_exe.relative_path());

            info!("reading Mach-O signature from {}", nested_exe.display());
            let macho_data = std::fs::read(&nested_exe)?;
            let macho_info = SignedMachOInfo::parse_data(&macho_data)?;

            self.resources
                .seal_macho(rel_path_normalized, &macho_info, optional)?;
        } else {
            warn!(
                "could not find main executable of presumed nested bundle: {}",
                rel_path.display()
            );
        }

        Ok(())
    }

    /// Seal a Mach-O binary matching a nested rule.
    fn seal_rules2_nested_macho(
        &mut self,
        full_path: &Path,
        rel_path: &Path,
        rel_path_normalized: &str,
        root_rel_path: &str,
        context: &mut BundleSigningContext,
        optional: bool,
    ) -> Result<(), AppleCodesignError> {
        let macho_info = if context
            .settings
            .path_exclusion_pattern_matches(root_rel_path)
        {
            warn!(
                "skipping signing of nested Mach-O binary because excluded by settings: {}",
                rel_path.display()
            );
            warn!("(an error will occur if this binary is not already signed)");
            warn!("(if you see an error, sign that Mach-O explicitly or remove it from the exclusion settings)");

            let dest_path = context.install_file(full_path, rel_path)?;
            let data = std::fs::read(dest_path)?;

            SignedMachOInfo::parse_data(&data)?
        } else {
            context.sign_and_install_macho(full_path, rel_path)?.1
        };

        self.resources
            .seal_macho(rel_path_normalized, &macho_info, optional)
    }

    /// Seal a file for version 2 rules.
    fn seal_rules2_file(
        &mut self,
        full_path: &Path,
        rel_path: &Path,
        rel_path_normalized: &str,
        root_rel_path: &str,
        omit: bool,
        optional: bool,
        context: &mut BundleSigningContext,
    ) -> Result<(), AppleCodesignError> {
        let mut need_install = !context.previously_installed_paths.contains(rel_path);

        // Only seal if the omit flag is unset.
        if !omit {
            // Unlike Apple's tooling, we recognize Mach-O binaries when the nested
            // flag isn't set and we automatically sign.
            //
            // Unless the path is marked for exclusion or shallow signing mode is
            // active.
            //
            // The reason we exclude in shallow mode is that shallow mode is supposed
            // to behave like Apple's `codesign` and that tool only signs the bundle's
            // "main" Mach-O binary, not other binaries.
            let sign_macho = need_install
                && crate::reader::path_is_macho(full_path)?
                && !context
                    .settings
                    .path_exclusion_pattern_matches(root_rel_path)
                && !context.settings.shallow();

            let read_path = if sign_macho {
                info!(
                    "non-nested file is a Mach-O binary; signing accordingly {}",
                    rel_path.display()
                );
                need_install = false;
                // We need to read the signed/installed version of the file since
                // signing will change its content.
                context.sign_and_install_macho(full_path, rel_path)?.0
            } else {
                info!("sealing regular file {}", rel_path_normalized);

                // If we need to install the file, seal the source file. Else since the
                // file is already installed, seal the destination file.
                //
                // For regular files this distinction doesn't matter. But for Mach-O
                // binaries it ensures we pick up the final signature, not the source
                // file.
                if need_install {
                    full_path.to_path_buf()
                } else {
                    context.dest_dir.join(rel_path)
                }
            };

            let digests = MultiDigest::from_path(read_path)?;

            let flavor = if self.digests.contains(&DigestType::Sha1) {
                FilesFlavor::Rules2WithSha1
            } else {
                FilesFlavor::Rules2
            };

            // When we seal the file, we treat it as a regular file since the
            // nested flag isn't set.
            self.resources
                .seal_regular_file(flavor, rel_path_normalized, digests, optional)?;
        }

        if need_install {
            context.install_file(full_path, rel_path)?;
        }

        Ok(())
    }

    fn seal_rules2_symlink(
        &mut self,
        full_path: &Path,
        rel_path: &Path,
        rel_path_normalized: &str,
        omit: bool,
        context: &mut BundleSigningContext,
    ) -> Result<(), AppleCodesignError> {
        let link_target = std::fs::read_link(full_path)?
            .to_string_lossy()
            .replace('\\', "/");

        if !omit {
            info!("sealing symlink {} -> {}", rel_path_normalized, link_target);
            self.resources
                .seal_symlink(rel_path_normalized, link_target);
        }
        context.install_file(full_path, rel_path)?;

        Ok(())
    }

    /// Perform sealing activity for an entry in rules v1.
    fn seal_rules1_file(
        &mut self,
        full_path: &Path,
        rel_path_normalized: &str,
        rule: CodeResourcesRule,
    ) -> Result<(), AppleCodesignError> {
        // Version 1 doesn't handle symlinks nor nested Mach-O binaries.
        // And version 2's handler installed files. So all we have to do here
        // is record SHA-1 digests in `<files>`.

        let digests = MultiDigest::from_path(full_path)?;

        self.resources.seal_regular_file(
            FilesFlavor::Rules,
            rel_path_normalized,
            digests,
            rule.optional,
        )?;

        Ok(())
    }

    /// Write CodeResources XML content to a writer.
    pub fn write_code_resources(&self, writer: impl Write) -> Result<(), AppleCodesignError> {
        self.resources.to_writer_xml(writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIREFOX_SNIPPET: &str = r#"
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
          <dict>
            <key>files</key>
            <dict>
              <key>Resources/XUL.sig</key>
              <data>Y0SEPxyC6hCQ+rl4LTRmXy7F9DQ=</data>
              <key>Resources/en.lproj/InfoPlist.strings</key>
              <dict>
                <key>hash</key>
                <data>U8LTYe+cVqPcBu9aLvcyyfp+dAg=</data>
                <key>optional</key>
                <true/>
              </dict>
              <key>Resources/firefox-bin.sig</key>
              <data>ZvZ3yDciAF4kB9F06Xr3gKi3DD4=</data>
            </dict>
            <key>files2</key>
            <dict>
              <key>Library/LaunchServices/org.mozilla.updater</key>
              <dict>
                <key>hash2</key>
                <data>iMnDHpWkKTI6xLi9Av93eNuIhxXhv3C18D4fljCfw2Y=</data>
              </dict>
              <key>TestOptional</key>
              <dict>
                <key>hash2</key>
                <data>iMnDHpWkKTI6xLi9Av93eNuIhxXhv3C18D4fljCfw2Y=</data>
                <key>optional</key>
                <true/>
              </dict>
              <key>MacOS/XUL</key>
              <dict>
                <key>cdhash</key>
                <data>NevNMzQBub9OjomMUAk2xBumyHM=</data>
                <key>requirement</key>
                <string>anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] /* exists */ or anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] /* exists */ and certificate leaf[field.1.2.840.113635.100.6.1.13] /* exists */ and certificate leaf[subject.OU] = "43AQ936H96"</string>
              </dict>
              <key>MacOS/SafariForWebKitDevelopment</key>
              <dict>
                <key>symlink</key>
                <string>/Library/Application Support/Apple/Safari/SafariForWebKitDevelopment</string>
              </dict>
            </dict>
            <key>rules</key>
            <dict>
              <key>^Resources/</key>
              <true/>
              <key>^Resources/.*\.lproj/</key>
              <dict>
                <key>optional</key>
                <true/>
                <key>weight</key>
                <real>1000</real>
              </dict>
            </dict>
            <key>rules2</key>
            <dict>
              <key>.*\.dSYM($|/)</key>
              <dict>
                <key>weight</key>
                <real>11</real>
              </dict>
              <key>^(.*/)?\.DS_Store$</key>
              <dict>
                <key>omit</key>
                <true/>
                <key>weight</key>
                <real>2000</real>
              </dict>
              <key>^[^/]+$</key>
              <dict>
                <key>nested</key>
                <true/>
                <key>weight</key>
                <real>10</real>
              </dict>
              <key>optional</key>
              <dict>
                <key>optional</key>
                <true/>
              </dict>
            </dict>
          </dict>
        </plist>"#;

    #[test]
    fn parse_firefox() {
        let resources = CodeResources::from_xml(FIREFOX_SNIPPET.as_bytes()).unwrap();

        // Serialize back to XML.
        let mut buffer = Vec::<u8>::new();
        resources.to_writer_xml(&mut buffer).unwrap();
        let resources2 = CodeResources::from_xml(&buffer).unwrap();

        assert_eq!(resources, resources2);
    }
}
