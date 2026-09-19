.. _apple_codesign_config_files:

=================================
``rcodesign`` Configuration Files
=================================

``rcodesign`` supports TOML configuration files.

.. _apple_codesign_config_files_loading_behavior:

File Loading Behavior
=====================

``rcodesign`` will automatically load configuration files in the
following order:

#. An ``rcodesign.toml`` file in the user's configuration directory.
   (``$XDG_CONFIG_HOME/rcodesign/`` or ``$HOME/.config/rcodesign/`` on
   Linux, ``FOLDERID_RoamingAppData/rcodesign/`` on Windows, and
   ``$HOME/Library/Application Support/rcodesign/`` on macOS.)
#. An ``rcodesign.toml`` in the directory ``rcodesign`` was invoked
   from.

The ``-C`` / ``--config-file`` global CLI argument forcefully loads
an alternative config file. If specified, the default configuration
files are not loaded.

.. _apple_codesign_config_files_environment_variables:

Config Settings From Environment Variables
==========================================

Every config setting can also be set via an environment variable.

Environment variables beginning with ``RCODESIGN_`` are mapped to
configuration settings. Dots (``.``) in config settings names are
converted to underscores (``_``) in environment variable names.

Profile names are not included in the environment variable name.

For example, for the config setting ``foo.bar`` corresponds to the environment
variable ``RCODESIGN_FOO_BAR``.

.. _apple_codesign_config_files_setting_precedence:

Config Setting Precedence
=========================

Configuration settings are loaded from multiple sources and last write
wins. Configurations are loaded in the following order:

1. Configuration files (the default file search paths or the explicit
   ``-C`` / ``--config-file`` file).
2. Environment variables.
3. CLI arguments.

In other words, explicit takes precedence over implicit.

Configuration sources are merged. Simple scalars and arrays are replaced.
Tables/dicts are union merged (each key is merged independently).

.. _apple_codesign_config_files_toml_structure:

TOML Structure
==============

Configuration files are `TOML <https://toml.io/>`_.

Top-level keys/sections in config files correspond to named *profiles*.

.. code-block:: toml

   # A profile named "default"
   [default]
   foo = "bar"

   # A profile named "test"
   [test]
   foo = "baz"

There are two special named profiles with special semantics:

``global``
   Settings in this profile override explicitly set settings in other profiles.
   If a value is set in this section it applies, well, globally to the entire
   file.

``default``
   Settings in this profile are inherited by all other profiles. Unlike
   ``[global]``, settings in this profile can be overwritten by other
   sections/profiles.

The default loaded profile is ``default``. An alternative profile can be
selected using the ``-P`` / ``--profile`` CLI argument.

Within each profile are TOML tables/dicts/maps/sections roughly corresponding
to per-command settings. The following sub-sections denote those keys.

``sign`` Command Settings
-------------------------

The ``sign`` table denotes settings for the ``rcodesign sign`` command.

This table can have the following keys:

``signer``
   Denotes the key/certificate used for signing. Is an instance of the
   :ref:`apple_codesign_rcodesign_config_files_signer` data structure.

   If not specified, ad-hoc code signing is performed.

``path``
   A table of per-path signing settings.

   Keys are paths/scopes the settings apply to. Values are instances of the
    :ref:`apple_codesign_rcodesign_config_files_path_settings` data structure.

.. code-block:: toml

   [default.sign]
   # Sign with a smartcard certificate at slot 9c.
   signer.smartcard = { slot = "9c" }

   # Sign the path at `Contents/MacOS/extra-binary` with a custom entitlements
   # plist.
   [default.sign.path."Contents/MacOS/extra-binary"]
   entitlements_xml_file = "extra-binary-entitlements.plist"

   # Enable the hardened runtime flag on the `Contents/MacOS/secure-binary`
   # Mach-O binary.
   [default.sign.path."Contents/MacOS/secure-binary"]
   code_signature_flags = ["runtime"]

   # Skip signing the nested `Electron Framework.framework` bundle.
   [default.sign.path."Contents/Frameworks/Electron Framework.framework/**"]
   exclude = true

``remote-sign`` Command Settings
--------------------------------

The ``remote-sign`` table denotes settings for the ``rcodesign remote-sign``
command.

This table can have the following keys:

``signer``
   Denotes the key/certificate used for signing. Is an instance of the
   :ref:`apple_codesign_rcodesign_config_files_signer` data structure.

.. code-block:: toml

   # Attempt to remote sign using a certificate in the macOS keychain with the
   # specified SHA-256 digest.
   [default.remote-sign]
   signer.macos_keychain = { sha256_fingerprint = "deadbeef..." }

.. _apple_codesign_rcodesign_config_files_data_structures:

Config Data Structures
======================

.. _apple_codesign_rcodesign_config_files_signer:

Signer
------

A *signer* denotes a source for a private signing key and its public
certificate(s).

Specific flavors of signer sources are defined in the sections below.

Typically you define a single source. However, multiple signer sources
can be combined and are effectively unioned together in an undefined order.

Smartcard Source
^^^^^^^^^^^^^^^^

The ``signer.smartcard`` key declares a key/certificate source in a smartcard,
like a YubiKey.

This key is a table/dict/map with the following keys:

``slot``
   The smartcard slot name.

   9c is the slot typically reserved for code signing. But other slots can
   be used.

   Run ``rcodesign smartcard-scan`` to see available certificates in your
   smartcard.

``pin``
   PIN string used to unlock the certificate.

   The smartcard slot settings may require a PIN to unlock the slot for key
   operations. If this is the case, this setting can be defined to provide said
   PIN.

   If not defined and a PIN is required, you will be prompted for the PIN as
   necessary.

.. code-block:: toml

   [default.sign]

   # Sign using the certificate in slot 9c. Prompt for PIN as necessary.
   signer.smartcard = { slot = "9c" }

   # Sign using the certificate in slot 9c and use the specified PIN value
   # instead of prompting.
   signer.smartcard = { slot = "9c", pin = "123456" }

.. important::

   The PIN is a secret and storing it in the config file in plain text can be
   dangerous. You may want to consider passing the PIN via an environment
   variable instead.

MacOS KeyChain Source
^^^^^^^^^^^^^^^^^^^^^

The ``signer.macos_keychain`` key declares a key/certificate source in a macOS
Keychain.

This key is a table/dict/map with the following keys:

``domains``
   Array of strings denoting the Keychain *domains* to search.

   Valid values are ``user``, ``system``, ``common``, ``dynamic``.

   The default is ``["user"]``.

``sha256_fingerprint``
   SHA-256 fingerprint of the certificate to use.

   You can find these by running ``rcodesign keychain-print-certificates``,
   locating the certificate you want to use, and copying the ``SHA-256
   fingerprint`` value.

   Strings should be 64 characters long.

.. code-block:: toml

   [default.sign]
   # Try to use a certificate in the user keychain having a SHA-256 fingerprint
   # of ``deadbeef...``.
   signer.macos_keychain = { sha256_fingerprint = "deadbeef..." }

PKCS#12 / P12 / PFX
^^^^^^^^^^^^^^^^^^^

The ``signer.p12`` key declares a key/certificate source in a PKCS#12 / P12 /
PFX file. These files commonly have the extensions ``.pfx`` and ``.p12``.

This key is a table/dict/map with the following keys:

``path``
   Path to the PKCS#12 / P12 / PFX file to load.

``password``
   Password to use to open the file.

``password_path``
   Path to a file containing the password to use.

If a password is not specified, you will be prompted to enter a password.

Examples:

.. code-block:: toml

   [default.sign]

   # Load the key/certificates from the file `signing.p12`. Don't supply
   # a password.
   signer.p12 = { path = "signing.p12" }

   # Same as the above but provide the path to a file containing the password.
   signer.p12 = { path = "signing.p12", "password_path" = "path/to/password/file" }

PEM Encoded Files Source
^^^^^^^^^^^^^^^^^^^^^^^^

The ``signer.pem`` key declares key/certificate sources in PEM encoded
files.

PEM files are text files with base64 content surrounded by
``-----BEGIN CERTIFICATE-----``, ``-----BEGIN PRIVATE KEY-----``, etc. Common
filename extensions are ``.pem``, ``.crt``, and ``.key``.

This key is a table/dict/map with the following keys:

``files``
   Array of paths to PEM files.

.. code-block:: toml

   [default.sign]
   signer.pem.files = ["cert.crt", "key.key"]

DER Encoded Certificate Source
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``signer.certificate_der_files`` key declares DER encoded X.509 public
certificates to load from files.

.. code-block:: toml

   signer.certificate_der_files = ["cert1.crt", "cert2.crt"]

Remote Code Signer Source
^^^^^^^^^^^^^^^^^^^^^^^^^

The ``signer.remote`` key declares a remote signing source.

This source engages the :ref:`apple_codesign_remote_signing` feature and
delegates code signing to a remote peer.

This key is a table/dict/map with the following keys:

``url``
   URL of a remote code signing relay server.

   Leave blank to use the default.

``public_key``
   Base64 encoded public key data used to encrypt a message to the remote
   signer.

``public_key_pem_path``
   File containing PEM encoded public key data used to encrypt a message to
   the remote signer.

``shared_secret``
   A shared secret value (i.e. a password/passphrase) used to encrypt a message
   to the remote signer.

Communication between initiating and signer peers is sent through a *relay
server*. All messages are encrypted in a way that the relay server cannot read
them.

Messages are encrypted either by using public key encryption (recommended) or a
shared secret value.

If using public key encryption, the public key data likely begins with ``MII``.

Windows Store Signer Source
^^^^^^^^^^^^^^^^^^^^^^^^^^^

The ``signer.windows_store`` key declares key/certificate sources in the Windows
certificate store.

This key is a table/dict/map with the following keys:

``stores``
   Array of strings denoting Windows Store names.

   Valid values are ``user``, ``machine``, and ``service``.

   Defaults to ``["user"]``.

``sha1_fingerprint``
   SHA-1 fingerprint of certificate in store to use.

.. _apple_codesign_rcodesign_config_files_path_settings:

Path Signing Settings
---------------------

This table/dict/map defines a collection of signing settings that apply to
a path or set of paths defined by a matching expression.

This table consists of the following keys:

``binary_identifier``
   Binary identifier for Mach-O binaries.

   This will typically be derived automatically using reasonable heuristics
   (mainly the file name). But it can be forced to a specific value using this
   setting.

   Note: it is possible to produce invalid bundle signatures when the identifier
   is manually set.

``code_requirements_file``
   Path to a file containing a code signing requirements expression.

   The requirements must be compiled to the binary form. Use the ``csreq``
   tool to do this from a macOS machine.

``code_signature_flags``
   Array of flags to add to the code signature.

``digests``
   Array of content digests to include in signatures.

   Typically reasonable defaults are derived automatically based on the
   targeting settings of the signed binary / bundle. But specific digests
   can be forced using this setting.

   If specifying multiple digests, ``sha1`` should be the first or signatures
   may not be valid on older operating systems.

``entitlements_xml_file``
   Path to a file containing plist XML entitlements to embed in a binary.

``info_plist_file``
   Path to an ``Info.plist`` file whose contents to capture in the code signature.

   The ``Info.plist`` is typically found automatically when signing bundles.
   When signing standalone Mach-O binaries you may need to provide it
   explicitly.

``launch_constraints_self_file``
   Path to a plist - either XML or binary - containing launch constraints to
   impose on the current executable.

``launch_constraints_parent_file``
   Path to a plist - either XML or binary - containing launch constraints to
   impose on the parent process.

``launch_constraints_responsible_file``
   Path to a plist - either XML or binary - containing launch constraints to
   impose on the responsible process.

``library_constraints_file``
   Path to a plist - either XML or binary - containing constraints to
   impose on loaded libraries.

``runtime_version``
   Apple operating system version representing the minimum version this binary
   can run on.

   This is typically derived automatically from metadata in the Mach-O binary.
