# Security policy

## Supported versions

CodeTruss supports the current CLI release. Upgrade before reporting a problem
that may already be fixed:

```bash
curl -fsSL https://codetruss.com/install.sh | sh
codetruss --version
```

## Report a vulnerability privately

Do not open a public issue for a suspected vulnerability. Email
`zack@codetruss.com` with:

- the affected CLI version and operating system;
- a minimal reproduction or evidence;
- the impact you believe is possible; and
- whether public disclosure is time-sensitive.

Do not include repository source, credentials, receipt signing keys, provider
keys, or unredacted diffs unless CodeTruss explicitly asks for a safe transfer
method. Receipt signatures and public signing keys are not secrets.

CodeTruss will acknowledge a valid report within three business days, provide
an initial severity assessment within seven business days, and coordinate a
fix and disclosure timeline with the reporter. Good-faith research that avoids
privacy violations, service disruption, data destruction, and access beyond
what is needed to demonstrate the issue is welcome.

## Scope

Security-sensitive surfaces include artifact/install integrity, receipt
signature or verification bypasses, false PASS conditions, provider-key or API
credential disclosure, unintended network transmission, path traversal,
command execution outside an approved verification policy, and organization
isolation failures in explicit receipt sync.
