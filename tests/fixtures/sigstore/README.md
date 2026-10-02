# Sigstore test fixtures

Copied unchanged from the test assets of
[sigstore-python](https://github.com/sigstore/sigstore-python) v4.5.0
(`test/assets/`), licensed under the Apache License 2.0.

| File | What it is |
|---|---|
| `bundle_v3_github.whl` | `rfc8785` 0.1.2 wheel (Trail of Bits, Apache-2.0). |
| `bundle_v3_github.whl.sigstore` | Production Sigstore bundle (message signature) for the wheel, signed by `https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2`. |
| `a.dsse.staging-rekor-v2.txt` | Sample text file. |
| `a.dsse.staging-rekor-v2.txt.sigstore.json` | Staging Sigstore bundle with a DSSE envelope whose in-toto subject does not match the sample file. Used as a "valid signature, wrong subject" case. |
