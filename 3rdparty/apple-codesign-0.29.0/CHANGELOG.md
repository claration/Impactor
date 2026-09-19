# `apple-codesign` History

<!-- next-header -->

## Unreleased

Released on ReleaseDate.

## 0.29.0

Released on 2024-11-29.

* When signing a bundle in `--shallow` mode, we no longer sign Mach-O binaries
  that aren't the *main* bundle binary. The new behavior is compatible with the
  behavior of Apple's `codesign`. (#148)
* Fixed a bug where signing of a bundle containing child bundles could sign and
  install certain files multiple times. This could result in a child bundle having
  an incorrect signature. (#149)
* MSRV 1.78 -> 1.81.
* `aws-sdk-s3` 1.24 -> 1.59.
* `clap` 4.4 -> 4.5.
* `minicbor` 0.24 -> 0.25.
* `thiserror` 1.0 -> 2.0.

## 0.28.0

Released on 2024-11-03.

* Fixed `env_logger` construction so `RUST_LOG` environment variable is
  respected. (#162)
* MSRV 1.70 -> 1.78.
* Improve logging of S3 upload failures. We should now hopefully print something
  more useful than `s3 upload error: unhandled error` on failures.
* `Info.plist` path handling should be more robust. This should fix errors
  like `I/O error: No such file or directory` when signing Frameworks. (#163)
* Enabled `http2` feature of `reqwest` crate. This may provide better HTTP/2.0
  compatibility.
* `aws-config` 1.1 -> 1.5.
* `aws-sdk-s3` 1.12 -> 1.24.
* `aws-smithy-types` 1.1 -> 1.2.
* `base64` 0.21 -> 0.22.
* `bitflags` 2.4 -> 2.6.
* `bytes` 1.5 -> 1.8.
* `cryptographic-message-syntax` 0.26 -> 0.27.
* `env_logger` 0.10 -> 0.11.
* `goblin` 0.8 -> 0.9.
* `minicbor` 0.20 -> 0.24.
* `object` 0.32 -> 0.36.
* `oid-registry` 0.6 -> 0.7.
* `once_cell` 1.19 -> 1.20.
* `plist` 1.6 -> 1.7.
* `rasn` 0.12 -> 0.20.
* `rayon` 1.8 -> 1.10.
* `regex` 1.10 -> 1.11.
* `reqwest` 0.11 -> 0.12.
* `security-framework` 2.9 -> 2.11.
* `subtle` 2.5 -> 2.6.
* `tempfile` 3.9 -> 3.13.
* `tokio` 1.35 -> 1.41.
* `tungstenite` 0.21 -> 0.24.
* `uuid` 1.6 -> 1.11.
* `walkdir` 2.4 -> 2.5.
* `widestring` 1.0 -> 1.1.
* `x509-certificate` 0.23 -> 0.24.
* `zeroize` 1.7 -> 1.8.
* `zip` 0.6 -> 2.2.

## 0.27.0

Released on 2024-01-17.

* Published a
  [GitHub Action for code signing and notarization](https://github.com/marketplace/actions/apple-code-signing)
  and wrote project documentation for how to use it. (#6)
* Fix to restore working builds with `--no-default-features`.
* Added `notary-list` command to print information about recently submitted
  notarizations to Apple. (#124)
* Fixed a bug where `.dSYM/` directories were incorrectly signed as
  bundles. (#128)
* The `sign` command has gained a `--shallow` argument to prevent traversing into
  nested entities when signing. It currently only prevents traversal into nested
  bundles. In the future, behavior may be expanded to also exclude signing of
  additional Mach-O binaries inside bundles, among other potential changes.
  Ultimately we want this signing mode to converge with the default behavior of
  Apple's tooling.
* The `sign` command has gained a `--for-notarization` argument that attempts to
  engage and enforce signing settings required for Apple notarization. The goal
  of the feature is to cut down on notarization failures after successful
  signing operations. If you encounter a notarization failure when using this
  new flag, consider filing a bug report.
* (API) `BundleSigner` now requires calling `collect_nested_bundles()` to register
  child bundles for signing instead of signing all nested bundles by default.
* aws-config 0.57 -> 1.1.
* aws-sdk-s3 0.36 -> 1.10.
* aws-smithy-http 0.57 -> 0.60.
* aws-smithy-types 0.57 -> 1.1.
* goblin 0.7 -> 0.8.
* scroll 0.11 -> 0.12.
* tungstenite 0.20 -> 0.21.
* windows-sys 0.48 -> 0.52.

## 0.26.0

Released on 2023-11-17.

* (New feature) On Windows, it is now possible to sign with code signing
  certificates stored in the Windows Certificate Store. The `sign` command
  (and other commands taking certificate sources) gained `--windows-store-name`
  and `--windows-store-sha1-fingerprint` arguments to specify a certificate in
  the Windows Certificate Store to use. New commands
  `windows-store-print-certificates` and
  `windows-store-export-certificate-chain` can discover and export certificates
  in the Windows Certificate Store. Feature contributed by El Mostafa Idrassi
  in #111.
* Fixed a bug where a `signing without an Apple signed certificate but signing
  settings contain a team name` warning was printed incorrectly.
* We now print a warning when signing using an expired certificate.
* Fixed a bug where `sign --code-signature-flags` could not be scoped. (#116)

## 0.25.1

Released on 2023-11-16.

* (Breaking change) The `sign --remote-signer` argument has been removed. It
  is now implicitly assumed via presence of a remote session initialization
  argument.
* Fixed a regression in 0.25.0 where remote signing didn't work due argument
  parsing errors.

## 0.25.0

Released on 2023-11-15.

(Binary assets for this release were never formally published due to a
regression in remote signing CLI argument handling.)

* (Breaking change) The `--extra-digest` argument has been removed.
  `--digest` can now be specified multiple times. `--digest` is now a
  scoped value.
* (Breaking change) Various signing settings no longer inherit to nested
  entities: `--entitlements-xml-file`, `--code-requirements-file`,
  `--code-resources-file`, `--code-signature-flags`, and `--info-plist-file`.
  The new behavior is much more conservative about which signing settings
  can be inherited and prevents unexpected results, such as all binaries
  in a bundle sharing the same entitlements or signing flags. Previous signers
  of bundles may find various signing settings disappearing from nested
  bundles or the non-main Mach-O binary within a bundle. It is highly encouraged
  to use the `rcodesign diff-signatures` command to compare results. If settings
  were dropped, add new scoped CLI arguments or use the new configuration
  file feature to add settings back in to specific paths.
* (New feature) Configuration file support added. TOML based configuration
  files can now define signers and signing settings in named *profiles*,
  allowing for automatic and near effortless reuse of common configurations.
  See the documentation for more.
* (New feature) Environment constraints support. We now support defining launch
  constraints and library constraints. We don't yet fully understand the
  interactions of constraints and code signing. If using constraints, we
  highly recommend comparing signature output with Apple's tooling to validate
  similar behavior. If you notice discrepancies, please file a GitHub issue!
  (#83)
* Detection of nested bundles now looks for `CFBundlePackageType` or
  `CFBundleIdentifier` in bundle `Info.plist` and ignores *bundles*
  lacking these. As a result, we no longer attempt signing of storybook
  *bundles* and other non-signable bundle-looking directories and no
  longer likely encounter errors in the process. (#38)
* CLI arguments for paths are now consistently named `--foo-file`
  instead of using a mix of `--foo-path`, `--foo-filename`, and
  potentially other variants. The old names are still recognized as
  aliases to maintain backwards compatibility.
* Changed heuristic for naming a binary identifier from its path to be
  more similar to Apple's. e.g. `foo1.2.dylib` will now resolve to `foo1`
  instead of `foo1.2`. We still don't use the binary UUID or digest of its
  load commands to compute the binary identifier like Apple does.
* When signing nested Mach-O binaries in a bundle, we now set the binary
  identifier from the filename rather than preserving the identifier in an
  existing signature. This helps ensure identifiers stay in sync and prevents
  bad signatures. (#109)
* `print-signature-info` now prints the entitlements plist decoded from DER.
  (#75)
* We no longer obtain placeholder time-stamp tokens when estimating the size
  of embedded signatures. Instead, we statically reserve 8192 bytes for the
  token. This may cause signatures to increase in size by a few kilobytes,
  as Apple's TSTs are ~4200 bytes. Signing should now be faster since we avoid
  an excessive network roundtrip. (#4)

## 0.24.0

Released on 2023-11-09.

* Add a `macho-universal-create` command to assemble single-arch Mach-O
  binaries into a single multi-arch / universal / fat binary. The command
  can be used as a replacement for Apple's `lipo -create`.
* When signing bundles, the `CodeResources` file for nested Mach-O binaries
  now emits the code directory hashes for every code directory. Before, if
  a Mach-O contained both SHA-1 and SHA-256 code directories, only the
  SHA-256 hash would be emitted. The new behavior matches Apple's tooling.
  (#95)
* The `generate-self-signed-certificate` command has gained the `--p12-file`
  and `--p12-password` arguments to write a self-signed certificate to a
  PKCS#12 / p12 / PFX file.
* The `generate-self-signed-certificate` command now supports generating
  RSA certificates. RSA certificates are now the default, to match what
  Apple uses by default.
* Reworked how code requirements expressions are automatically derived.
  This should result in self-signed certificates having correct requirements
  expressions that no longer imply they were signed by Apple's CAs. In
  addition, some Apple signing certificates should now opt into using a
  more appropriate code requirements expression than before. This may have
  fixed validation errors with some signatures. (#99)
* Team name is no longer included in signature when signing with a non
  Apple signed certificate. This matches the behavior of Apple's tools. (#101)
* Fixed a bug where the `AnchorCertificateHash` code requirements expression
  was being incorrectly formatted as `anchor <slot> H"<hash>"` instead of
  `certificate <slot> = H"<hash>"`.
* Added awareness of new Apple CA certificates:
  `Apple Application Integration CA 7 - G1 Certificate`,
  `Worldwide Developer Relations - G7`, and `Worldwide Developer Relations - G8`.
* `print-signature-info` now prints some integer values as strings containing
  both the integer and hex forms. Additional fields are added to help debug
  signature writing.
* Conflicting binary identifiers within a universal Mach-O are now reconciled
  to the initially seen value. This matches the behavior of Apple's tooling
  and fixes a bug where drift between the values could cause bundle validation
  to fail. (#103)
* Fixed a bug where bundle signing would fail to overwrite preexisting state
  in Mach-O binaries, leading to failed signature verification. This likely
  only occurred when attempting to re-sign already signed binaries. (#104)
* When signing bundles, non Mach-O resources files are no longer fully buffered
  in memory to compute their content digests. This can drastically cut down
  on memory usage when signing large resources files. Mach-O binaries are
  still fully buffered in memory. (#45)
* Removed `verify` warning about insecure code digests. The warning was spurious
  and didn't take into account the nuanced logic for emitting SHA-1 digests.
  (#50)
* cryptographic-message-syntax 0.25 -> 0.26.
* x509-certificate 0.22 -> 0.23.

## 0.23.0

Released on 2023-11-06.

* Notarization features are now optional and can be controlled via the
  enabled-by-default `notarize` crate feature. (#78)
* Minimum supported Rust version changed from 1.62.1 to 1.70.0.
* CLI argument parsing has been rewritten to use clap's derive mode
  instead of the builder mode. The intent was to mostly preserve existing
  CLI behavior. However, some minor changes - possibly bugs - may have
  occurred as a result of this refactor.
* `AppleCodesignError::AwsS3Error` now stores a `Box<T>`.
* Added a hidden `debug-create-macho` command for generating Mach-O files.
  The command (and new code behind it) is intended to facilitate writing
  tests of Mach-O signing.
* Added a hidden `debug-create-info-plist` command for generating Info.plist
  files. The command is intended to be used to facilitate testing.
* The `--code-signature-flags` argument of the `sign` command now correctly
  applies multiple values. Before, flags were set to the final specified
  value.
* Added several trycmd based tests for testing CLI and signing behaviors.
  The trycmd tests may download a prebuilt Rust coreutils binary from
  github.com when executing on platforms with prebuilt binaries.
* The `--data` argument of the `extract` command is now a positional argument.
* Added a hidden `debug-create-code-requirements` command for generating
  binary code requirements files. The command is intended to facilitate testing.
* The `print-signature-info` command should now work on bundles. It may have
  stopped working as part of an upgrade to `serde_yaml`. The YAML output may
  have changed slightly.
* `CodeResources` files now emit `"` instead of `&quot;` for parity with Apple
  tooling.
* SHA-1 digests are now automatically enabled when signing a Mach-O binary
  without platform targeting. This mimics the behavior of Apple's tooling.
  Before, we would only automatically activate SHA-1 digests when there was
  a Mach-O load command targeting a too-old platform version which didn't
  support SHA-256 digests.
* An empty CMS blob is now automatically added when signing in ad-hoc mode.
  Before, no CMS blob would be present. The new behavior matches that of
  Apple's tooling.
* Code signature data is now aligned to 16 byte boundaries in Mach-O binaries.
  This matches the behavior of Apple tooling.
* HTTP requests now use the operating system's trusted X.509 certificates
  instead of a default set (based off Mozilla's maintained list). This should
  allow connections to HTTP proxies using custom/private certificate authorities
  to work, assuming certificates are installed on the local system. (#85)
* Added a hidden `debug-create-entitlements` command for generating entitlements
  plist files. The command is intended to facilitate testing.
* The `print-signature-info` command YAML output now encodes entitlements XML
  as an array of strings for easier readability.
* A custom signing time can now be specified to force using a specific
  time instead of the current time. The CMS signing and settings APIs have
  changed accordingly. The `sign` command now accepts a `--signing-time`
  argument to control the signing time.
* The `generate-self-signed-certificate` command gained a
  `--pem-unified-filename` argument to write a PEM encoded file containing
  both the private key and public certificate.
* Fixed a bug where files would be identified as Mach-O when they weren't.
* Bundle signing logic has been significantly overhauled to hopefully make
  it conform with Apple tooling's behavior. This likely fixed several bugs
  with bundle signing.
* Fixed a bundle signing bug where overwriting symlinks would incorrectly
  result in an `Error: I/O error: File exists (os error 17)` or similar.
* When signing bundles, symlinks in directories marked as *nested* should
  now get properly sealed and installed. (#10)
* When signing bundles, Mach-O binaries outside of *nested* directories
  (e.g. `Libraries/libFoo.dylib`) are automatically detected as Mach-O
  binaries and signed. This behavior conforms with our stated behavior of
  recursively signing all signable entities. However, it is incompatible
  with Apple's tooling, which only signs Mach-O binaries located in
  specific directories having the *nested* flag set. This change should
  result in *it just works* single command signing of many complex
  bundles.
* Added a hidden `debug-file-tree` command to print simple directory
  trees. The command is used by snapshot tests to validate bundle signing
  behavior.
* The CLI default log level has been changed to `warn`. As a result,
  command output is less verbose. `-v` restores the prior behavior. And
  `-vvv` is now needed to activate `trace` logging (previously `-vv` was
  the highest log level).
* The `sign --exclude` argument is now honored for Mach-O binaries within
  bundles. Previously, it only applied to bundle paths.
* The default `CodeResources` rules for bundles lacking a `Resources/`
  now properly have trailing `/` on rules referencing `.lproj` directories.
  Previously, these directories were likely not handled correctly. (#42)
* Fixed a bug where attempting to sign Mach-O binaries having a `__TEXT` segment
  whose start offset was >0 resulted in a `Mach-O segment corruption` error.
  We can now properly sign such files. (#91)
* `verify` command now errors if not given the path of a Mach-O binary.
* `verify` command now prints a warning that its known to be buggy.
* aws crates 0.53 -> 0.57.
* bitflags 1.3 -> 2.0.
* cryptographic-message-syntax 0.19 -> 0.25.
* dialoguer 0.10 -> 0.11.
* dirs 4.0 -> 5.0.
* elliptic-curve 0.12 -> 0.13.
* goblin 0.6 -> 0.7.
* minicbor 0.19 -> 0.20.
* once_cell 1.16 -> 1.17.
* pkcs1 0.4 -> 0.7.
* p256 0.11 -> 0.13.
* pem 1.1 -> 3.0.
* pkcs8 0.9 -> 0.10.
* rasn 0.6 -> 0.11.
* ring 0.16 -> 0.17.
* rsa 0.7 -> 0.9.
* signature 1.6 -> 2.0.
* spake2 0.3 -> 0.4.
* spki 0.6 -> 0.7.
* tungstenite 0.18 -> 0.20.
* x509-certificate 0.16 -> 0.22.
* yubikey 0.7 -> 0.8.

## 0.22.0

Released on 2022-12-21.

* Cargo.toml now defines patch version for all dependencies.
* goblin crate upgraded from 0.5 to 0.6.
* App Store Connect API code extracted to its own crate, `app-store-connect`.
  The new crate lives in the same repository as this one. (#54)

## 0.21.0

Released on 2022-12-18.

* Embedded entitlements XML is now used when estimating the size of signatures.
  Previously, this data could cause us to not reserve enough space for the
  signature, causing signing to fail. (#32, #40)
* Bundle stapling is now capable of stapling any bundle with a main executable,
  not just app bundles with a main executable. (#41)
* The `smartcard-scan`, `smartcard-generate-key`, and `smartcard-import`
  commons are now always present, even when compiled without the `smartcard`
  crate feature enabled. The commands will error at runtime if smartcard support
  is not enabled.
* Minimum supported Rust version changed from 1.61.0 to 1.62.1.
* Changed handling of code requirements around bundle signing to hopefully fix
  `the sealed resource directory is invalid` errors. This should hopefully
  enable signing adhoc app bundles with frameworks. Before, if a Mach-O inside
  a bundle contained no designated requirements, no designated requirements
  were emitted. After, designated requirements are derived automatically from
  the digests of code directories in Mach-O binaries. Additionally, an empty
  designated requirements blob can be emitted. (#44)
* Shallow framework bundles are now properly recognized as such. This fixes
  a common issue with signing iOS bundles. (#46)

## 0.20.0

Released on 2022-10-02.

* Zip notarization support. APIs and the `notary-submit` CLI command now recognize
  zip files and will upload them to the Notary API without modifications. Neither
  zip file signing nor stapling are supported. Feature contributed by @deansheather.
  (#20)
* When signing the main binary in a bundle, we now prefer the identifier from
  the bundle's `Info.plist` over the identifier already present in the Mach-O.
  This ensures that the identifier is consistent across multiple Mach-O in a
  fat/universal binary and is consistent with the value advertised in the
  `Info.plist`. (#12, #22)
* It is now possible to sign Mach-O binaries where the `__LINKEDIT` segment
  wasn't the final advertised segment in Mach-O headers. Previously, a
  `__LINKEDIT isn't final Mach-O segment` error would occur when attempting to
  sign a Mach-O whose headers declared a `__LINKEDIT` segment before other
  segments, even if `__LINKEDIT` was truly at the highest file offset. (This
  scenario is common in Go binaries.) (#17)
* The `--pem-source` argument can now decode PKCS#1 private keys as encoded
  with `RSA PRIVATE KEY`. Previously, an `unhandled PEM tag RSA PRIVATE KEY;
  ignoring` warning would have been printed. (#26)
* Most code from `main.rs` has been moved into `cli.rs` so it is part of the
  library.
* `aws-config`, `aws-smithy-http` upgraded from 0.47 -> 0.49.
* `aws-sdk-s3` upgraded from 0.17 -> 0.19.
* `clap` upgraded from 3.1 -> 4.0. This entailed a lot of code changes to
  argument parsing. Argument parsing behavior should be backwards compatible
  (unless otherwise documented in this section) and any change in behavior is
  a bug.

## 0.19.0

(Released 2022-09-18)

* Canonical home of project moved from https://github.com/indygreg/PyOxidizer to
  https://github.com/indygreg/apple-platform-rs.
* Universal Mach-O creation logic inlined from `tugger-apple` crate to remove
  crate dependency.
* Switched from `tugger-file-manifest` crate to `simple-file-manifest`. (The
  crate was effectively renamed.)

## 0.18.0

(Released 2022-09-17)

* Mach-O digesting code now digests file-level data without looking at segment
  boundaries. This fixes a bug where we were computing the incorrect digests when
  Mach-O segments weren't aligned at 4096 byte boundaries. (Go binaries commonly
  don't have 4k aligned segment boundaries.) (#634)
* Optimizations to computing cryptographic digests of binaries. We eliminate a
  a redundant digest that was used to compute the final size of the code digests.
  The `rayon` crate is now used to perform digests in parallel, yielding a
  ~linear speedup with the number of CPUs available.
* (API) `app_store_connect` module has been split up into multiple modules
  to facilitate better grouping.
* (API) Various changes for upgrades of crates related to cryptography.
* der crate upgraded from 0.5 to 0.6.
* elliptic-curve crate upgraded from 0.11 to 0.12.
* oid-registry crate upgraded from 0.5 to 0.6.
* p256 crate upgraded from 0.10 to 0.11.
* pkcs1 crate upgraded from 0.3 to 0.4.
* pkcs8 crate upgraded from 0.8 to 0.9.
* spki crate upgraded from 0.5 to 0.6.
* yubikey crate upgraded from 0.4 to 0.6.
* (API) The `code_hash` module had its content folded into the new function
  `MachOBinary::code_digests()`.

## 0.17.0

(Released 2022-08-07)

* **Major feature**: Notarization is now implemented in Rust and no longer
  requires Apple's *Transporter* application. Going forward, you only need
  the `rcodesign` executable (or this crate embedded as a library) and an
  App Store Connect API Key to notarize. Major thanks to Robin Lambertz
  (@roblabla) for contributing the bulk of the implementation in #593.
* As a result of native notarization, integration with Apple's *Transporter*
  has been removed. The `find-transporter` command has been removed. Rust
  APIs related to Transporter, the *app metadata* XML format it used, and App
  Store Connect APIs previously used have been removed.
* As a result of native notarization, UI and implementation details of
  notarization have changed. The output when uploading assets is much more
  concise. Before, code existed to normalize uploaded assets to a data format
  required by Transporter. As a side-effect, assets were somewhat validated
  locally before upload. In the new world, minimal checks are performed locally.
  This can result in errors (such as attempting to upload an asset without a
  code signature) occurring later than they did previously.
* A new `encode-app-store-connect-api-key` command can be used to encode an
  App Store Connect API Key in a single JSON object. These keys are used for
  notarization and having all the API Key metadata in a single file / JSON
  blob means you have 1 entity to define your App Store Connect API Key instead
  of 3, making UI simpler.
* The `notarize` command has been renamed to `notary-submit`. This follows
  the terminology of Apple's `notarytool` and mimics the nomenclature used
  by the Notary API. The old `notarize` command is an alias to
  `notary-submit`.
* The `notary-submit` command now has an `--api-key-path` argument defining the
  path to a JSON file containing the unified App Store Connect API Key emitted
  by the `encode-app-store-connect-api-key` command. We recommend using this
  method for specifying the API Key going forward, as it is simpler. The old
  method was required for use with Apple's Transporter application, which we
  no longer use so we're no longer bound by its requirements. The old method
  will likely be dropped from a future release.
* A new `notary-wait` command can be used to wait on a previous notary
  submission to complete and to view its log info. This command can be useful if
  `notary-submit` times out or otherwise fails and you want to query the
  status of a previous notarization.
* A new `notary-log` command will fetch the notarization log of a previous
  submission from the Notary API server.
* Fixed signing of Mach-O binaries having a gap between segments. (This is known
  to commonly occur in Go binaries.) In previous versions, we would compute
  digests of the file incorrectly and would encounter an assertion when copying
  Mach-O data to the output binary. Both of these issues should now be fixed.
  (#588 and #616)
* minicbor crate upgraded from version 0.15. This created API differences in
  remote signing code.
* The APIs around Mach-O file parsing have been significantly overhauled. It
  is probably best to diff the `macho` module to see the full differences.
  There are now `MachFile` and `MachOBinary` types serving as interfaces
  to custom Mach-O functionality. Most code interfacing with a Mach-O file now
  uses these types. The `AppleSignable` trait has been deleted as it is no
  longer needed since we have the dedicated `MachOBinary` type.

## 0.16.0

(Released 2022-06-05)

* Distributed macOS binaries no longer dynamically link `liblzma.5.dylib`.

## 0.15.0

(Released 2022-06-04)

* XAR files are now always signed through a temporary file in order to avoid
  corruption of the XAR file.

## 0.14.0

(Released 2022-04-24)

* Fixed a bug where symlinks weren't been written in notarization zip file
  files properly. This prevented bundles containing symlinks from notarizing
  correctly.
* The filename used in notarization uploads is now normalized to avoid
  rejection due to spaces and colons.
* Support for remote signing. The feature is documented extensively in the
  Sphinx documentation. Essentially, 2 independent machines communicate with
  each other with end-to-end encrypted messages via a websocket bridged through
  a central server. Signing requests are sent to a remote machine which is in
  possession of the signing key. Signatures are made on the remote machine and
  transmitted back to the originating machine. Remote signing enables signing
  to be performed more securely by facilitating signing without having to give
  the initiating machine access to the signing key.
* Default log output format has changed. Lines are no longer prefixed with the
  time, log level, or logging module by default. A `-v/--verbose` global flag
  has been added to increase the verbosity of logging. This can restore the
  printing of the prefixes. This crate uses
  `env_logger <https://crates.io/crates/env_logger>`_, so it is possible
  to customize default behavior via environment variables.
* The possible values for the `--code-signature-flags` are now advertised in
  help output.
* Written Mach-O files should now always have their filesystem permissions
  preserved. Before, we may not have preserved file permissions in all code
  paths writing Mach-O files.
* A new `keychain-print-certificates` command can be used to print
  certificates available in macOS keychains.
* Initial support for using macOS keychain certificates for code signing.
  Previously, we required that certificates be exported from keychain in
  order to sign. We now support signing using SecurityFramework APIs so
  keys don't have to leave the keychain. Due to a limitation in the Rust
  bindings to SecurityFramework, decryption using keychain keys is not
  supported. So the *public key agreement* method of remote code signing
  will not yet work with keychain-based keys. The new `--keychain-domain`
  and `--keychain-fingerprint` arguments can be used to specify how to
  search for and use keychain hosted keys.

## 0.13.0

(Released 2022-04-10)

* Restores behavior of <= 0.10.0 where the binary identifier of non main
  executable Mach-O files in bundles is automatically derived from the file name
  if the Mach-O doesn't already have a binary identifier. This fixes a regression
  in 0.11 and 0.12.
* When signing a Mach-O, `Info.plist` data embedded in the Mach-O is now
  automatically used when no `Info.plist` data is provided externally.
* The handling of preserving metadata from previous Mach-O signatures has been
  refactored. In the new world, existing Mach-O state is imported into the
  signing settings data structure at signing time and the signing operation
  largely uses the settings data structure as the canonical source for state.
  Explicitly set signing settings should take precedence over a previous Mach-O
  signature.
* Fixed a bug where empty Mach-O segments could result in an error when writing
  signed Mach-O files. (#544)
* Mach-O and bundle signing now automatically use OS targeting metadata embedded
  in Mach-O binaries to activate SHA-1 + SHA-256 digests when necessary. If a
  Mach-O binary indicates it targets an older OS version that lacks support for
  SHA-256 digests (e.g. macOS <10.11.4), we will automatically use SHA-1 as the
  primary digest method and include SHA-256 digests for modern operating systems.
  As a result of this change, binaries and bundles that were targeting macOS
  <10.11.4, iOS/tvOS <11, and watchOS now properly contain SHA-1 digests as the
  primary digest type.
* In bundle signing, `CodeResources` files now capture the `cdhash` of the
  SHA-256 code directory. Before, they would always use the primary code
  directory, which might be using SHA-1. The `cdhash` value must be from the
  SHA-256 code directory to be valid. This change should result in more bundles
  having working signatures.
* DER encoded entitlements are now only added when signing executable files.
  Previously, we added DER encoded entitlements whenever entitlements data
  was present. It appears DER encoded entitlements are only written on Mach-O
  binaries that are executables.
* Executable segment flags are now derived from the Mach-O file type and
  entitlements plist data. We no longer blindly copy executable segment flags
  from previous signatures. We no longer have CLI arguments to define executable
  segment flags. This ensures that the entitlements plist and executable
  segment flags are always in sync.
* CMS signatures are now properly constructed when there are multiple code
  directories. Before, the CMS signed attributes didn't capture all code
  directories and the signatures would be incomplete. This resulted in Apple's
  tooling rejecting the CMS signatures as invalid.

## 0.12.0

* Binary identifier strings are now always enclosed in double quotes when
  serializing code requirements expressions to strings. Previously, the lack of
  double quotes could result in malformed strings that might fail to parse.
* Fixed a bundle signing bug where the digests of nested bundles were taken from the
  source directory and not the destination directory. This would result in digests
  of nested bundles being incorrect if signing bundles to a different output directory
  than from the input.

## 0.11.0

* The `--pfx-file`, `--pfx-password`, and `--pfx-password-file` arguments
  have been renamed to `--p12-file`, `--p12-password`, and
  `--p12-password-file`, respectively. The old names are aliases and should
  continue to work.
* Initial support for using smartcards for signing. Smartcard integration may only
  work with YubiKeys due to how the integration is implemented.
* A new `rcodesign smartcard-scan` command can be used to scan attached
  smartcards and certificates they have available for code signing.
* `rcodesign sign` now accepts a `--smartcard-slot` argument to specify the
  slot number of a certificate to use when code signing.
* A new `rcodesign smartcard-import` command can be used to import a code signing
  certificate into a smartcard. It can import private-public key pair or just import
  a public certificate (and use an existing private key on the smartcard device).
* A new `rcodesign generate-certificate-signing-request` command can be used
  to generate a Certificate Signing Request (CSR) which can be uploaded to Apple
  and exchanged for a code signing certificate signed by Apple.
* A new `rcodesign smartcard-generate-key` command for generating a new private
  key on a smartcard.
* Fixed bug where `--code-signature-flags`, `--executable-segment-flags`,
  `--runtime-version`, and `--info-plist-path` could only be specified once.
* `rcodesign sign` now accepts an `--extra-digest` argument to provide an
  extra digest type to include in signatures. This facilitates signing with
  multiple digest types via e.g. `--digest sha1 --extra-digest sha256`.
* Fixed an embarrassing number of bugs in bundle signing. Bundle signing was
  broken in several ways before: resource files in shallow app bundles (e.g. iOS
  app bundles) weren't handled correctly; symlinks weren't preserved correctly;
  framework signing was completely busted; nested bundles weren't signed in the
  correct order; entitlements in Mach-O binaries weren't preserved during
  signing; `CodeResources` files had extra entries in `<files>` that shouldn't
  have been there, and likely a few more.
* Add `--exclude` argument to `rcodesign sign` to allow excluding nested
  bundles from signing.
* Notarizing bundles containing symlinks no longer fails with a cryptic I/O
  error message. We now produce zip files with symlink entries. However, there
  may still be issues getting Apple to notarize bundles with symlinks.
* Fixed a bug where we could silently write a softly corrupt code signature
  by copying digests that were too short. Previously, if you attempted to re-sign
  a Mach-O having SHA-1 digests, those SHA-1 digests could get copied to the
  new signature using SHA-256 digests and the bytes belonging to each digest
  would get mangled and wouldn't be correct. We now prevent writing digests
  that don't match the expected digest length and when copying digests we
  look for alternate code directories having the digest of the new signature.

## 0.10.0

* Support for signing, notarizing, and stapling `.dmg` files.
* Support for signing, notarizing, and stapling flat packages (`.pkg` installers).
* Various symbols related to common code signature data structures have been moved from the
  `macho` module to the new `embedded_signature` module.
* Signing settings types have been moved from the `signing` module to the new
  `signing_settings` module.
* `rcodesign sign` no longer requires an output path and will now sign an entity
  in place if only a single positional argument is given.
* The new `rcodesign print-signature-info` command prints out easy-to-read YAML
  describing code signatures detected in a given path. Just point it at a file with
  code signatures and it can print out details about the code signatures within.
* The new `rcodesign diff-signatures` command prints a diff of the signature content
  of 2 filesystem paths. It is essentially a built-in diffing mechanism for the output
  of `rcodesign print-signature-info`. The intended use of the command is to aid
  in debugging differences between this tool and Apple's canonical tools.

## 0.9.0

* Imported new Apple certificates. `Developer ID - G2 (Expiring 09/17/2031 00:00:00 UTC)`,
  `Worldwide Developer Relations - G4 (Expiring 12/10/2030 00:00:00 UTC)`,
  `Worldwide Developer Relations - G5 (Expiring 12/10/2030 00:00:00 UTC)`,
  and `Worldwide Developer Relations - G6 (Expiring 03/19/2036 00:00:00 UTC)`.
* Changed names of enum variants on `apple_codesign::apple_certificates::KnownCertificate`
  to reflect latest naming from https://www.apple.com/certificateauthority/.
* Refreshed content of Apple certificates `AppleAAICA.cer`, `AppleISTCA8G1.cer`, and
  `AppleTimestampCA.cer`.
* Renamed `apple_codesign::macho::CodeSigningSlot::SecuritySettings` to
  `EntitlementsDer`.
* Add `apple_codesign::macho::CodeSigningSlot::RepSpecific`.
* `rcodesign extract` has learned a `macho-target` output to display information
  about targeting settings of a Mach-O binary.
* The code signature data structure version is now automatically modernized when
  signing a Mach-O binary targeting iOS >= 15 or macOS >= 12. This fixes an issue
  where signatures of iOS 15+ binaries didn't meet Apple's requirements for this
  platform.
* Logging switched to `log` crate. This changes program output slightly and removed
  an `&slog::Logger` argument from various functions.
* `SigningSettings` now internally stores entitlements as a parsed plist. Its
  `set_entitlements_xml()` now returns `Result<()>` in order to reflect errors
  parsing plist XML. Its `entitlements_xml()` now returns `Result<Option<String>>`
  instead of `Option<&str>` because XML serialization is fallible and the resulting
  XML is owned instead of a reference to a stored value. As a result of this change,
  the embedded entitlements XML specified via `rcodesign sign --entitlement-xml-path`
  may be encoded differently than it was previously. Before, the content of the
  specified file was embedded verbatim. After, the file is parsed as plist XML and
  re-serialized to XML. This can result in encoding differences of the XML. This
  should hopefully not matter, as valid XML should be valid XML.
* Support for DER encoded entitlements in code signatures. Apple code signatures
  encode entitlements both in plist XML form and DER. Previously, we only supported
  the former. Now, if entitlements are being written, they are written in both XML
  and DER. This should match the default behavior of `codesign` as of macOS 12.
  (#513, #515)
* When signing, the entitlements plist associated with the signing operation
  is now parsed and keys like `get-task-allow` and
  `com.apple.private.skip-library-validation` are now automatically propagated
  to the code directory's executable segment flags. Previously, no such propagation
  occurred and special entitlements would not be fully reflected in the code
  signature. The new behavior matches that of `codesign`.
* Fixed a bug in `rcodesign verify` where code directory verification was
  complaining about `slot digest contains digest for slot not in signature`
  for the `Info (1)` and `Resources (3)` slots. The condition it was
  complaining about was actually valid. (#512)
* Better supported for setting the hardened runtime version. Previously, we
  only set the hardened runtime version in a code signature if it was present
  in the prior code signature. When signing unsigned binaries, this could
  result in the hardened runtime version not being set, which would cause
  Apple tools to complain about the hardened runtime not being enabled. Now,
  if the `runtime` code signature flag is set on the signing operation and
  no runtime version is present, we derive the runtime version from the version
  of the Apple SDK used to build the binary. This matches the behavior of
  `codesign`. There is also a new `--runtime-version` argument to
  `rcodesign sign` that can be used to override the runtime version.
* When signing, code requirements are now printed in their human friendly
  code requirements language rather than using Rust's default serialization.
* `rcodesign sign` will now automatically set the team ID when the signing
  certificate contains one.
* Added the `rcodesign find-transporter` command for finding the path to
  Apple's *Transporter* program (which is used for notarization).
* Initial support for stapling. The `rcodesign staple` command can be used
  to staple a notarization ticket to an entity. It currently only supports
  stapling app bundles (`.app` directories). The command will automatically
  contact Apple's servers to obtain a notarization ticket and then staple
  any found ticket to the requested entity.
* Initial support for notarizing. The `rcodesign notarize` command can
  be used to upload an entity to Apple. The command can optionally wait on
  notarization to finish and staple the notarization ticket if notarization
  is successful. The command currently only supports macOS app bundles
  (`.app` directories).

## 0.8.0

* Crate renamed from `tugger-apple-codesign` to `apple-codesign`.
* Fixed bug where signing failed to update the `vmsize` field of the
  `__LINKEDIT` mach-o segment. Previously, a malformed mach-o file could
  be produced. (#514)
* Added `x509-oids` command for printing Apple OIDs related to code signing.
* Added `analyze-certificate` command for printing information about
  certificates that is relevant to code signing.
* Added the `tutorial` crate with some end-user documentation.
* Crate dependencies updated to newer versions.

## 0.7.0 and Earlier

* Crate was published as `tugger-apple-codesign`. No history kept in this file.
