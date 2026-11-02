# Security policy

TrustMint reads cloud configuration and reports on it. It does not request, sign or use
tokens, and its only network access is the optional, read-only `trustmint collect aws`.

## Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/ahmedhany-cys/trustmint/security/advisories/new)
rather than a public issue. Include the input that triggers the problem (with real
identifiers removed) and the output you expected.

A missed finding (a trust TrustMint rates narrower than it really is) is treated as a
security bug.

## Handling real data

Snapshots contain role ARNs, account IDs and repository names. Keep them out of public
issues and repositories; the examples in this repository are synthetic.
