// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Launch constraints and library constraints.

use {
    crate::{
        plist_der::{der_decode_plist, der_encode_plist},
        AppleCodesignError, Result,
    },
    plist::{Dictionary, Value},
    std::path::Path,
};

/// Represents the DER encoded form of environment constraints.
///
/// Instances can be converted into a [Value] using `.into()`.
#[derive(Clone, Debug)]
pub struct EncodedEnvironmentConstraints {
    /// We're not sure what this is.
    ///
    /// Value always appears to be 0.
    pub ccat: u64,

    /// We're not sure what this is.
    ///
    /// Value always appears to be 1.
    ///
    /// We hypothesize it might be a compatibility version number.
    pub comp: u64,

    /// The user-provided constraints, as a mapping.
    pub requirements: Dictionary,

    /// We're not sure what this is.
    ///
    /// Value always appears to be 1.
    ///
    /// We hypothesize it is a version number.
    pub vers: u64,
}

impl Default for EncodedEnvironmentConstraints {
    fn default() -> Self {
        Self {
            ccat: 0,
            comp: 1,
            requirements: Default::default(),
            vers: 1,
        }
    }
}

impl From<EncodedEnvironmentConstraints> for Value {
    fn from(value: EncodedEnvironmentConstraints) -> Self {
        let mut dict = Dictionary::default();

        dict.insert("ccat".into(), value.ccat.into());
        dict.insert("comp".into(), value.comp.into());
        dict.insert("reqs".into(), value.requirements.into());
        dict.insert("vers".into(), value.vers.into());

        dict.into()
    }
}

impl TryFrom<Value> for EncodedEnvironmentConstraints {
    type Error = AppleCodesignError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let mut res = Self::default();

        match value {
            Value::Dictionary(dict) => {
                for (k, v) in dict {
                    match k.as_str() {
                        "ccat" => match v {
                            Value::Integer(v) => {
                                res.ccat = v.as_signed().ok_or_else(|| {
                                    AppleCodesignError::EnvironmentConstraint(
                                        "failed to convert ccat to i64".into(),
                                    )
                                })? as u64;
                            }
                            _ => {
                                return Err(AppleCodesignError::EnvironmentConstraint(
                                    "ccat is not an integer".into(),
                                ));
                            }
                        },
                        "comp" => match v {
                            Value::Integer(v) => {
                                res.comp = v.as_signed().ok_or_else(|| {
                                    AppleCodesignError::EnvironmentConstraint(
                                        "failed to convert comp to i64".into(),
                                    )
                                })? as u64;
                            }
                            _ => {
                                return Err(AppleCodesignError::EnvironmentConstraint(
                                    "comp is not an integer".into(),
                                ));
                            }
                        },
                        "reqs" => match v {
                            Value::Dictionary(v) => {
                                res.requirements = v;
                            }
                            _ => {
                                return Err(AppleCodesignError::EnvironmentConstraint(
                                    "reqs is not a dictionary".into(),
                                ));
                            }
                        },
                        "vers" => match v {
                            Value::Integer(v) => {
                                res.vers = v.as_signed().ok_or_else(|| {
                                    AppleCodesignError::EnvironmentConstraint(
                                        "failed to convert vers to i64".into(),
                                    )
                                })? as u64;
                            }
                            _ => {
                                return Err(AppleCodesignError::EnvironmentConstraint(
                                    "vers is not an integer".into(),
                                ));
                            }
                        },
                        _ => {
                            return Err(AppleCodesignError::EnvironmentConstraint(format!(
                                "unknown key in plist: {}",
                                k
                            )));
                        }
                    }
                }

                Ok(res)
            }
            _ => Err(AppleCodesignError::EnvironmentConstraint(
                "plist value is not a dictionary".to_string(),
            )),
        }
    }
}

impl EncodedEnvironmentConstraints {
    /// Attempt to decode an instance from DER.
    pub fn from_der(data: impl AsRef<[u8]>) -> Result<Self> {
        let value = der_decode_plist(data)?;

        Self::try_from(value)
    }

    /// Obtain an instance from a requirements plist.
    pub fn from_requirements_plist(value: Value) -> Result<Self> {
        match value {
            Value::Dictionary(v) => Ok(Self {
                requirements: v,
                ..Default::default()
            }),
            _ => Err(AppleCodesignError::EnvironmentConstraint(
                "supplied plist is not a dictionary".into(),
            )),
        }
    }

    /// Attempt to construct an instance by reading requirements plist data from a file.
    ///
    /// Source file can be XML or binary encoding.
    pub fn from_requirements_plist_file(path: impl AsRef<Path>) -> Result<Self> {
        let value = Value::from_file(path.as_ref())?;
        Self::from_requirements_plist(value)
    }

    /// Encode the instance to DER.
    pub fn der_encode(&self) -> Result<Vec<u8>> {
        let value = Value::from(self.clone());

        der_encode_plist(&value)
    }

    /// Obtain just the requirements as a plist [Value].
    pub fn requirements_plist(&self) -> Value {
        Value::Dictionary(self.requirements.clone())
    }
}
