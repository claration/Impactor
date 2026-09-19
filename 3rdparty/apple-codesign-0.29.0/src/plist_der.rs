// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Plist DER encoding. */

use {
    crate::error::AppleCodesignError,
    num_traits::cast::ToPrimitive,
    plist::Value,
    rasn::{
        ber::de::DecodeError,
        ber::enc::EncodeError,
        de::Error as DeError,
        enc::Error as EncError,
        types::{fields::{Field, Fields}, Class, Constraints, Constructed, Integer, Tag},
        AsnType, Codec, Decode, Decoder, Encode, Encoder,
    },
    std::collections::BTreeMap,
};

#[derive(AsnType, Debug, Decode)]
struct DictionaryEntry {
    #[rasn(tag(universal, 12))]
    key: String,
    value: WrappedValue,
}

/// Represents a plist dictionary in the rasn domain.
#[derive(Debug)]
struct Dictionary(plist::Dictionary);

impl AsnType for Dictionary {
    const TAG: Tag = Tag {
        class: Class::Context,
        value: 16,
    };
}

impl Constructed for Dictionary {
    // This is incorrect, but a required field is needed to be specified to
    // communicate to rasn it needs to know that there is fields to decode.
    const FIELDS: Fields = Fields::from_static(&[Field::new_optional_type::<()>("key")]);
}

impl Encode for Dictionary {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<(), E::Error> {
        // Sort it alphabetically.
        let map = self.0.iter().collect::<BTreeMap<_, _>>();

        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            for (k, v) in map {
                let wrapped = WrappedValue::try_from(v.clone())?;

                encoder.encode_sequence::<Self, _>(Tag::SEQUENCE, |encoder| {
                    encoder.encode_utf8_string(Tag::UTF8_STRING, Constraints::NONE, k)?;
                    wrapped.encode(encoder)?;
                    Ok(())
                })?;
            }

            Ok(())
        })?;

        Ok(())
    }
}

impl Decode for Dictionary {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_sequence::<Self, _, _>(tag, Some(|| Self(plist::Dictionary::new())), |decoder| {
            let mut dict = plist::Dictionary::new();

            loop {
                let entry = decoder.decode_optional::<DictionaryEntry>()?;

                if let Some(entry) = entry {
                    let value = plist::Value::try_from(entry.value)?;

                    dict.insert(entry.key, value);
                } else {
                    break;
                }
            }

            Ok(Self(dict))
        })
    }
}

/// Represents a [Value] in the rasn domain.
#[derive(AsnType, Debug, Decode, Encode)]
#[rasn(choice)]
enum WrappedValue {
    Array(Vec<WrappedValue>),
    Dictionary(Dictionary),
    #[rasn(tag(universal, 1))]
    Boolean(bool),
    #[rasn(tag(universal, 2))]
    Integer(Integer),
    #[rasn(tag(universal, 12))]
    String(String),
}

impl TryFrom<Value> for WrappedValue {
    type Error = EncodeError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        match value {
            Value::Array(v) => Ok(Self::Array(
                v.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            Value::Dictionary(v) => Ok(Self::Dictionary(Dictionary(v))),
            Value::Boolean(v) => Ok(Self::Boolean(v)),
            Value::Integer(v) => {
                let integer = Integer::from(v.as_signed().ok_or(EncodeError::custom(
                    "could not obtain integer representation from plist integer",
                    Codec::Der,
                ))?);

                Ok(Self::Integer(integer))
            }
            Value::String(v) => Ok(Self::String(v)),
            Value::Data(_) => Err(EncodeError::custom(
                "encoding of data values not supported",
                Codec::Der,
            )),
            Value::Date(_) => Err(EncodeError::custom(
                "encoding of date values not supported",
                Codec::Der,
            )),
            Value::Real(_) => Err(EncodeError::custom(
                "encoding of real values not supported",
                Codec::Der,
            )),
            Value::Uid(_) => Err(EncodeError::custom(
                "encoding of uid values not supported",
                Codec::Der,
            )),
            _ => Err(EncodeError::custom(
                "encoding of unknown value type not supported",
                Codec::Der,
            )),
        }
    }
}

impl TryFrom<WrappedValue> for Value {
    type Error = DecodeError;

    fn try_from(value: WrappedValue) -> Result<Self, Self::Error> {
        match value {
            WrappedValue::Array(v) => Ok(Self::Array(
                v.into_iter()
                    .map(Self::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            WrappedValue::Dictionary(v) => Ok(Self::Dictionary(v.0)),
            WrappedValue::Boolean(v) => Ok(Self::Boolean(v)),
            WrappedValue::Integer(v) => {
                let v = v.to_i64().ok_or(DecodeError::custom(
                    "could not convert BigInt to i64",
                    Codec::Der,
                ))?;

                Ok(Self::Integer(plist::Integer::from(v)))
            }
            WrappedValue::String(v) => Ok(Self::String(v)),
        }
    }
}

/// Represents a top-level plist in the rasn domain.
struct WrappedPlist(WrappedValue);

impl AsnType for WrappedPlist {
    const TAG: Tag = Tag {
        class: Class::Application,
        value: 16,
    };
}

impl Constructed for WrappedPlist {
    const FIELDS: Fields = Fields::from_static(&[
        Field::new_required_type::<Integer>("key"),
        Field::new_required_type::<WrappedValue>("value"),
    ]);
}

impl TryFrom<Value> for WrappedPlist {
    type Error = EncodeError;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

impl TryFrom<WrappedPlist> for Value {
    type Error = DecodeError;

    fn try_from(value: WrappedPlist) -> Result<Self, Self::Error> {
        if let WrappedValue::Dictionary(d) = value.0 {
            Ok(Self::Dictionary(d.0))
        } else {
            Err(DecodeError::custom(
                "wrapped value not a dictionary",
                Codec::Der,
            ))
        }
    }
}

impl Encode for WrappedPlist {
    fn encode_with_tag_and_constraints<E: Encoder>(
        &self,
        encoder: &mut E,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<(), E::Error> {
        encoder.encode_sequence::<Self, _>(tag, |encoder| {
            encoder.encode_integer(Tag::INTEGER, Constraints::NONE, &Integer::from(1))?;
            self.0.encode(encoder)
        })?;

        Ok(())
    }
}

impl Decode for WrappedPlist {
    fn decode_with_tag_and_constraints<D: Decoder>(
        decoder: &mut D,
        tag: Tag,
        _constraints: Constraints,
    ) -> Result<Self, D::Error> {
        decoder.decode_sequence::<Self, _, _>(tag, None::<fn() -> Self>, |decoder| {
            let _: Integer = decoder.decode_integer(Tag::INTEGER, Constraints::NONE)?;
            let value = WrappedValue::decode(decoder)?;

            Ok(Self(value))
        })
    }
}

/// Encode a top-level plist [Value] to DER.
pub fn der_encode_plist(value: &Value) -> Result<Vec<u8>, AppleCodesignError> {
    rasn::der::encode_scope(|encoder| {
        let wrapped = WrappedPlist::try_from(value.clone())?;
        wrapped.encode(encoder)
    })
    .map_err(|e| AppleCodesignError::PlistDer(format!("{e}")))
}

/// Decode DER to a plist [Value].
pub fn der_decode_plist(data: impl AsRef<[u8]>) -> Result<Value, AppleCodesignError> {
    rasn::der::decode::<WrappedPlist>(data.as_ref())
        .and_then(Value::try_from)
        .map_err(|e| AppleCodesignError::PlistDer(format!("{e}")))
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::{
            embedded_signature::{Blob, CodeSigningSlot},
            macho::MachFile,
        },
        anyhow::{anyhow, Result},
        plist::{Date, Uid},
        std::{
            process::Command,
            time::{Duration, SystemTime},
        },
    };

    const DER_EMPTY_DICT: &[u8] = &[112, 5, 2, 1, 1, 176, 0];
    const DER_BOOL_FALSE: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 1, 1, 0,
    ];
    const DER_BOOL_TRUE: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 1, 1, 255,
    ];
    const DER_INTEGER_0: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 2, 1, 0,
    ];
    const DER_INTEGER_NEG1: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 2, 1, 255,
    ];
    const DER_INTEGER_1: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 2, 1, 1,
    ];
    const DER_INTEGER_42: &[u8] = &[
        112, 15, 2, 1, 1, 176, 10, 48, 8, 12, 3, 107, 101, 121, 2, 1, 42,
    ];
    const DER_STRING_EMPTY: &[u8] = &[112, 14, 2, 1, 1, 176, 9, 48, 7, 12, 3, 107, 101, 121, 12, 0];
    const DER_STRING_VALUE: &[u8] = &[
        112, 19, 2, 1, 1, 176, 14, 48, 12, 12, 3, 107, 101, 121, 12, 5, 118, 97, 108, 117, 101,
    ];
    const DER_ARRAY_EMPTY: &[u8] = &[112, 14, 2, 1, 1, 176, 9, 48, 7, 12, 3, 107, 101, 121, 48, 0];
    const DER_ARRAY_FALSE: &[u8] = &[
        112, 17, 2, 1, 1, 176, 12, 48, 10, 12, 3, 107, 101, 121, 48, 3, 1, 1, 0,
    ];
    const DER_ARRAY_TRUE_FOO: &[u8] = &[
        112, 22, 2, 1, 1, 176, 17, 48, 15, 12, 3, 107, 101, 121, 48, 8, 1, 1, 255, 12, 3, 102, 111,
        111,
    ];
    const DER_DICT_EMPTY: &[u8] = &[
        112, 14, 2, 1, 1, 176, 9, 48, 7, 12, 3, 107, 101, 121, 176, 0,
    ];
    const DER_DICT_BOOL: &[u8] = &[
        112, 26, 2, 1, 1, 176, 21, 48, 19, 12, 3, 107, 101, 121, 176, 12, 48, 10, 12, 5, 105, 110,
        110, 101, 114, 1, 1, 0,
    ];
    const DER_MULTIPLE_KEYS: &[u8] = &[
        112, 37, 2, 1, 1, 176, 32, 48, 8, 12, 3, 107, 101, 121, 1, 1, 0, 48, 9, 12, 4, 107, 101,
        121, 50, 1, 1, 255, 48, 9, 12, 4, 107, 101, 121, 51, 2, 1, 42,
    ];

    /// Signs a binary with custom entitlements XML and retrieves the entitlements DER.
    ///
    /// This uses Apple's `codesign` executable to sign the current binary then uses
    /// our library for extracting the entitlements DER that it generated.
    #[allow(unused)]
    fn sign_and_get_entitlements_der(value: &Value) -> Result<Vec<u8>> {
        let this_exe = std::env::current_exe()?;

        let temp_dir = tempfile::tempdir()?;

        let in_path = temp_dir.path().join("original");
        let entitlements_path = temp_dir.path().join("entitlements.xml");
        std::fs::copy(this_exe, &in_path)?;
        {
            let mut fh = std::fs::File::create(&entitlements_path)?;
            value.to_writer_xml(&mut fh)?;
        }

        let args = vec![
            "--verbose".to_string(),
            "--force".to_string(),
            // ad-hoc signing since we don't care about a CMS signature.
            "-s".to_string(),
            "-".to_string(),
            "--generate-entitlement-der".to_string(),
            "--entitlements".to_string(),
            format!("{}", entitlements_path.display()),
            format!("{}", in_path.display()),
        ];

        let status = Command::new("codesign").args(args).output()?;
        if !status.status.success() {
            return Err(anyhow!("codesign invocation failure"));
        }

        // Now extract the data from the Apple produced code signature.

        let signed_exe = std::fs::read(&in_path)?;
        let mach = MachFile::parse(&signed_exe)?;
        let macho = mach.nth_macho(0)?;

        let signature = macho
            .code_signature()?
            .expect("unable to find code signature");

        let slot = signature
            .find_slot(CodeSigningSlot::EntitlementsDer)
            .expect("unable to find der entitlements blob");

        match slot.clone().into_parsed_blob()?.blob {
            crate::embedded_signature::BlobData::EntitlementsDer(der) => {
                Ok(der.serialize_payload()?)
            }
            _ => Err(anyhow!(
                "failed to obtain entitlements DER (this should never happen)"
            )),
        }
    }

    // This test is failing in CI. Older versions of macOS / codesign likely have
    // a different DER encoding mechanism.
    // #[test]
    #[cfg(target_os = "macos")]
    #[allow(unused)]
    fn apple_der_entitlements_encoding() -> Result<()> {
        // `codesign` prints "unknown exception" if we attempt to serialize a plist where
        // the root element isn't a dict.
        let mut d = plist::Dictionary::new();

        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_EMPTY_DICT
        );

        d.insert("key".into(), Value::Boolean(false));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_BOOL_FALSE
        );

        d.insert("key".into(), Value::Boolean(true));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_BOOL_TRUE
        );

        d.insert("key".into(), Value::Integer(0u32.into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_0
        );

        d.insert("key".into(), Value::Integer((-1i32).into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_NEG1
        );

        d.insert("key".into(), Value::Integer(1u32.into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_1
        );

        d.insert("key".into(), Value::Integer(42u32.into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_42
        );

        // Floats fail to encode to DER.
        d.insert("key".into(), Value::Real(0.0f32.into()));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::Real((-1.0f32).into()));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::Real(1.0f32.into()));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::String("".into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_STRING_EMPTY
        );

        d.insert("key".into(), Value::String("value".into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_STRING_VALUE
        );

        // Uids fail to encode with `UidNotSupportedInXmlPlist` message.
        d.insert("key".into(), Value::Uid(Uid::new(0)));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::Uid(Uid::new(1)));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::Uid(Uid::new(42)));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        // Date doesn't appear to work due to
        // `Failed to parse entitlements: AMFIUnserializeXML: syntax error near line 6`. Perhaps
        // a bug in the plist crate?
        d.insert(
            "key".into(),
            Value::Date(Date::from(SystemTime::UNIX_EPOCH)),
        );
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());
        d.insert(
            "key".into(),
            Value::Date(Date::from(
                SystemTime::UNIX_EPOCH + Duration::from_secs(86400 * 365 * 30),
            )),
        );
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        // Data fails to encode to DER with `unknown exception`.
        d.insert("key".into(), Value::Data(vec![]));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());
        d.insert("key".into(), Value::Data(b"foo".to_vec()));
        assert!(sign_and_get_entitlements_der(&Value::Dictionary(d.clone())).is_err());

        d.insert("key".into(), Value::Array(vec![]));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_EMPTY
        );

        d.insert("key".into(), Value::Array(vec![Value::Boolean(false)]));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_FALSE
        );

        d.insert(
            "key".into(),
            Value::Array(vec![Value::Boolean(true), Value::String("foo".into())]),
        );
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_TRUE_FOO
        );

        let mut inner = plist::Dictionary::new();
        d.insert("key".into(), Value::Dictionary(inner.clone()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_DICT_EMPTY
        );

        inner.insert("inner".into(), Value::Boolean(false));
        d.insert("key".into(), Value::Dictionary(inner.clone()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_DICT_BOOL
        );

        d.insert("key".into(), Value::Boolean(false));
        d.insert("key2".into(), Value::Boolean(true));
        d.insert("key3".into(), Value::Integer(42i32.into()));
        assert_eq!(
            sign_and_get_entitlements_der(&Value::Dictionary(d.clone()))?,
            DER_MULTIPLE_KEYS
        );

        Ok(())
    }

    #[test]
    fn der_encoding() -> Result<()> {
        let mut d = plist::Dictionary::new();

        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_EMPTY_DICT
        );
        assert_eq!(
            der_decode_plist(DER_EMPTY_DICT)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Boolean(false));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_BOOL_FALSE
        );
        assert_eq!(
            der_decode_plist(DER_BOOL_FALSE)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Boolean(true));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_BOOL_TRUE
        );
        assert_eq!(
            der_decode_plist(DER_BOOL_TRUE)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Integer(0u32.into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_0
        );
        assert_eq!(
            der_decode_plist(DER_INTEGER_0)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Integer((-1i32).into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_NEG1
        );
        assert_eq!(
            der_decode_plist(DER_INTEGER_NEG1)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Integer(1u32.into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_1
        );
        assert_eq!(
            der_decode_plist(DER_INTEGER_1)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Integer(42u32.into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_INTEGER_42
        );
        assert_eq!(
            der_decode_plist(DER_INTEGER_42)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Real(0.0f32.into()));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::Real((-1.0f32).into()));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::Real(1.0f32.into()));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::String("".into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_STRING_EMPTY
        );
        assert_eq!(
            der_decode_plist(DER_STRING_EMPTY)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::String("value".into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_STRING_VALUE
        );
        assert_eq!(
            der_decode_plist(DER_STRING_VALUE)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Uid(Uid::new(0)));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::Uid(Uid::new(1)));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::Uid(Uid::new(42)));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert(
            "key".into(),
            Value::Date(Date::from(SystemTime::UNIX_EPOCH)),
        );
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));
        d.insert(
            "key".into(),
            Value::Date(Date::from(
                SystemTime::UNIX_EPOCH + Duration::from_secs(86400 * 365 * 30),
            )),
        );
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        // Data fails to encode to DER with `unknown exception`.
        d.insert("key".into(), Value::Data(vec![]));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));
        d.insert("key".into(), Value::Data(b"foo".to_vec()));
        assert!(matches!(
            der_encode_plist(&Value::Dictionary(d.clone())),
            Err(AppleCodesignError::PlistDer(_))
        ));

        d.insert("key".into(), Value::Array(vec![]));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_EMPTY
        );
        assert_eq!(
            der_decode_plist(DER_ARRAY_EMPTY)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Array(vec![Value::Boolean(false)]));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_FALSE
        );
        assert_eq!(
            der_decode_plist(DER_ARRAY_FALSE)?,
            Value::Dictionary(d.clone())
        );

        d.insert(
            "key".into(),
            Value::Array(vec![Value::Boolean(true), Value::String("foo".into())]),
        );
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_ARRAY_TRUE_FOO
        );
        assert_eq!(
            der_decode_plist(DER_ARRAY_TRUE_FOO)?,
            Value::Dictionary(d.clone())
        );

        let mut inner = plist::Dictionary::new();
        d.insert("key".into(), Value::Dictionary(inner.clone()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_DICT_EMPTY
        );
        assert_eq!(
            der_decode_plist(DER_DICT_EMPTY)?,
            Value::Dictionary(d.clone())
        );

        inner.insert("inner".into(), Value::Boolean(false));
        d.insert("key".into(), Value::Dictionary(inner.clone()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_DICT_BOOL
        );
        assert_eq!(
            der_decode_plist(DER_DICT_BOOL)?,
            Value::Dictionary(d.clone())
        );

        d.insert("key".into(), Value::Boolean(false));
        d.insert("key2".into(), Value::Boolean(true));
        d.insert("key3".into(), Value::Integer(42i32.into()));
        assert_eq!(
            der_encode_plist(&Value::Dictionary(d.clone()))?,
            DER_MULTIPLE_KEYS
        );
        assert_eq!(
            der_decode_plist(DER_MULTIPLE_KEYS)?,
            Value::Dictionary(d.clone())
        );

        Ok(())
    }
}
