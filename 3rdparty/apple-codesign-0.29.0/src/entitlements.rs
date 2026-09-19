// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

/*! Code entitlements handling. */

use {crate::code_directory::ExecutableSegmentFlags, plist::Value};

/// Convert an entitlements plist to [ExecutableSegmentFlags].
///
/// Some entitlements plist values imply features in executable segment flags.
/// This function resolves those implied features.
pub fn plist_to_executable_segment_flags(value: &Value) -> ExecutableSegmentFlags {
    let mut flags = ExecutableSegmentFlags::empty();

    if let Value::Dictionary(d) = value {
        if matches!(d.get("get-task-allow"), Some(Value::Boolean(true))) {
            flags |= ExecutableSegmentFlags::ALLOW_UNSIGNED;
        }
        if matches!(d.get("run-unsigned-code"), Some(Value::Boolean(true))) {
            flags |= ExecutableSegmentFlags::ALLOW_UNSIGNED;
        }
        if matches!(
            d.get("com.apple.private.cs.debugger"),
            Some(Value::Boolean(true))
        ) {
            flags |= ExecutableSegmentFlags::DEBUGGER;
        }
        if matches!(d.get("dynamic-codesigning"), Some(Value::Boolean(true))) {
            flags |= ExecutableSegmentFlags::JIT;
        }
        if matches!(
            d.get("com.apple.private.skip-library-validation"),
            Some(Value::Boolean(true))
        ) {
            flags |= ExecutableSegmentFlags::SKIP_LIBRARY_VALIDATION;
        }
        if matches!(
            d.get("com.apple.private.amfi.can-load-cdhash"),
            Some(Value::Boolean(true))
        ) {
            flags |= ExecutableSegmentFlags::CAN_LOAD_CD_HASH;
        }
        if matches!(
            d.get("com.apple.private.amfi.can-execute-cdhash"),
            Some(Value::Boolean(true))
        ) {
            flags |= ExecutableSegmentFlags::CAN_EXEC_CD_HASH;
        }
    }

    flags
}
