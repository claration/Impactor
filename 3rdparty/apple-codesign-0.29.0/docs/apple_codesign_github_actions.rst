.. _apple_codesign_github_actions:

==========================================
Signing and Notarizing with GitHub Actions
==========================================

The `indygreg/apple-code-sign-action <https://github.com/marketplace/actions/apple-code-signing>`_
GitHub Action provides a relatively turnkey way to sign and notarize using
``rcodesign``.

Signing
=======

You will need to make a signing certificate available to GitHub Actions.

You can either install the signing certificate *locally* in the GitHub Actions
runner/workflow or you can use the :ref:`apple_codesign_remote_signing` feature.

Local Certificate Signing
-------------------------

There are multiple ways to make a local code signing certificate available to
GitHub Actions. Each have various security / convenience trade-offs.

We recommend storing the certificate private key in a GitHub Actions Secret.
Storing the private key this way prevents offline attacks.

Find the PEM representation of your signing certificate. It will look something
like:

.. code-block::

   -----BEGIN PRIVATE KEY-----
   MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCkdCzwAgHcNbpH
   awCPZISFqL6vPHstX1F9FjjGiOqQZ60xtXMsj1vpfxhpBZwxO/Q3RDn1ogvCluE5
   ...
   -----END PRIVATE KEY-----

Use the instructions at
https://docs.github.com/en/actions/security-guides/using-secrets-in-github-actions#creating-secrets-for-a-repository
to create a secret with this private key content.

Assuming the secret is named ``PRIVATE_KEY``, you can write the private key to
a file and pass it to the GitHub Action doing something like the following:

.. code-block:: yaml

   steps:
     - name: Write PEM encoded private key data to a file
       env:
         PRIVATE_KEY: ${{ secrets.PRIVATE_KEY }}
       run: |
         echo $PRIVATE_KEY | tr ' ' '\n' > key.pem

     - name: Code signing
       uses: indygreg/apple-code-sign-action@v1
       with:
         pem_file: |
           key.pem
           cert.pem

Remote Signing
--------------

In *remote signing* mode, a remote machine has access to the code signing
certificate so that GitHub Actions never has access to it. This is theoretically
more secure since if GitHub gets hacked, nobody has an offline copy of your
signing certificate!

See :ref:`apple_codesign_remote_signing_session_agreement` for an overview
of the mechanisms for initiating remote signing.

We recommend use of public key agreement over shared secrets because it should
be more secure.

You can even use your code signing certificate's public key as the public key
to use.

.. code-block:: yaml

   steps:
     - name: Code signing
       uses: indygreg/apple-code-sign-action@v1
       with:
         remote_sign_public_key: |
           MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt2CB7Q9oBDpA6Pkd4spG
           CWF+LbOnJUGkUPeCn7frIv8CT6HMxaCE8KokTuNo8nVqJW9Ocy/oFHO2SiJ0H2EM
           FgaWIVgfiJuZKIMwzDzIEtgV48VE9V+9ARaI5JOFm+buivAtlCdTzpUASscIqVb1
           00Lqyf8oAd679bywsxEyigVTxAFQ+qHFfyk0/D8Z8tg7e+osoXAFoH/E6fdKaUMv
           EUwoMvpulvT/+gqAS9qnnYd2ugbHNtjIrD1YK5JF5oi2JePDS37uF4QmuEXGAh3e
           DlIRDozAqC0Oeg0zPVuFBFZy1iVy4NS8aYY9NiaKH3EMDVkzz077znw/cJp9+wHZ
           WQIDAQAB

Notarizing
==========

Notarizing requires you to have an App Store Connect API Key.

Follow the instructions at :ref:`apple_codesign_app_store_connect_api_key`.

Assuming you ran ``rcodesign encode-app-store-connect-api-key`` to obtain a
unified JSON file, we recommend copying that JSON data into a GitHub Actions
secret.

Then simply write out that secret to a file and reference it from the GitHub
Actions config:

.. code-block:: yaml

   steps:
     - name: Write API Key to file
       env:
         API_KEY: ${{ secrets.APP_STORE_API_KEY }}
       run: echo $API_KEY > app_store_key.json

     - name: Notarize
       uses: indygreg/apple-code-sign-action@v1
       with:
         app_store_connect_api_key_json_file: app_store_key.json
         # Remember to enable notarization and to disable signing if you just
         # want to notarize.
         sign: false
         notarize: true
         staple: true
         input_path: MyApp.app
