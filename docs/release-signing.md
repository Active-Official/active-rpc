# Release signing

Every release tag in this repository is signed. This document records the key,
why it is an SSH key, and how anyone can verify a tag.

## The key

| Property | Value |
|---|---|
| Type | Ed25519 |
| Fingerprint | `SHA256:msxYmwYS/hzVOmO8hm9sjOfOOlK1u6TohPU8BgT7n3Y` |
| Public key | [`../release-signing.allowed_signers`](../release-signing.allowed_signers) |
| Identity | `im.david.demarco@gmail.com` |
| Created | 2026-10-27 |

The private key lives outside the repository, at
`%USERPROFILE%\.ssh\active-release-signing` on the release machine. It signs
tags only; commits are not signed with it.

## Why SSH and not GPG

GnuPG is installed on the release machine (the build bundled with Git for
Windows), but its `keyboxd` backend cannot start there: the daemon derives its
socket name from the home directory, and a Windows path contains a drive colon,
which `keyboxd` rejects (`':' are not allowed in the socket name`). A GPG key can
be created, but no GPG operation that needs the key database works, so GPG
signatures could neither be produced nor verified on the machine that publishes
the release.

Git 2.34+ signs tags with an SSH key (`gpg.format = ssh`), and verification uses
stock OpenSSH plus the allowed-signers file checked in here. That is a smaller
dependency, works on every platform, and is the format GitHub displays as
"Verified".

## Signing a release (maintainer)

```bash
git config gpg.format ssh
git config user.signingkey "$HOME/.ssh/active-release-signing.pub"
git config tag.gpgsign true
git tag -s -m "active-rpc 1.1.3" v1.1.3
git push --follow-tags
```

## Verifying a tag (anyone)

```bash
git -c gpg.ssh.allowedSignersFile=release-signing.allowed_signers tag -v v1.1.3
```

A good tag prints:

```
object <commit>
type commit
tag v1.1.3
tagger ...
Good "git" signature for im.david.demarco@gmail.com with ED25519 key SHA256:msxYmwYS/hzVOmO8hm9sjOfOOlK1u6TohPU8BgT7n3Y
```

To verify against a GitHub-hosted key instead, import the public key above into
a `allowed_signers` file of your own; the tag carries the signature and needs no
network access.

## Rotation

1. Generate a new key and add its public half as a new line in
   `release-signing.allowed_signers` (several lines are allowed).
2. Sign the next tag with the new key.
3. Remove the old line once no supported release depends on it.

A rotated key never invalidates an existing tag: the old public key stays in the
file's history, and the tag's signature is verified against the line that was
current when it was signed.
