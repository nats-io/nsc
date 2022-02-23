Release Signing
===============

We sign releases with static signing keys, inside GitHub Actions.

If cosign keyless mode and GitHub can use OIDC identities from GitHub
identifying the organization, then we will probably switch to that, because it
avoids one organization holding secrets.

The signing keys we use here live in GitHub Actions as secrets, and in a
1Password vault used by the NATS Maintainers at Synadia Communications.

---

We want release signatures to be verifiable by as many people as possible,
while using contemporary cryptography.  It is fine to sign with multiple
systems.

We mostly sign checksums.

Our new channel-managing installer tries to balance "a modern tool for the
future" with "a tool which everyone will have installed", so will verify
cosign signatures and SSH file signatures.  The cosign tool supports OCI
containers and has enough other useful features that we hope it's what the
industry moves towards.

We're seriously tempted to add OpenPGP signatures, since we have WKD set up
for nats.io, but three signatures at once might be overdoing things a little.
If there's demand, we will revisit.

---

## The Public Keys

In both cases, we use no passphrase on the private key: for the CI system, the
passphrase would have to live in the same place as the private key material,
so provides a false sense of security.

```sh
ssh-keygen -t ed25519 -f nsc-release-signing-ssh -C 'nsc release builds SSH signing key' -N ''
COSIGN_PASSWORD='' cosign generate-key-pair
for f in cosign.*; do mv -v $f nsc-release-$f; done
tail -n +1 *.pub
```

gives these public keys

```
==> nsc-release-cosign.pub <==
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+Zi4Lxy2j3MYdUSWkKi/aQfA73s7
aNxCtk9yNPc3I08TsWISvhqbxquDHGOeDdf0FQh6mHMWclke2mMIYGDuLA==
-----END PUBLIC KEY-----

==> nsc-release-signing-ssh.pub <==
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKLLmYCvqzSVa+ZwHDToc6DLjGBMII7B9jSSRbZ8ylbN nsc release builds SSH signing key
```

These keys were generated 2022-02-23 by Phil Pennock, pdp@nats.io, and deleted
from local disk after storing in GitHub and 1Password.  At time of writing,
four people have access to that Vault.
