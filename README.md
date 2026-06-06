# mailserver-check

A CLI tool to audit the DNS-based email security configuration of a domain. It checks all relevant records and evaluates their policies — giving you an instant overview of whether a domain is protected against spoofing, phishing, and man-in-the-middle attacks on mail transport.

---

## Why this matters

Modern email security is built on a stack of DNS records that work together. If any of them are missing or misconfigured, your domain is vulnerable:

| Without... | Attackers can... |
|---|---|
| **SPF** | Send emails that appear to come from your domain from any server |
| **DKIM** | Forge message content without the recipient noticing |
| **DMARC** | Bypass SPF/DKIM entirely — without DMARC, SPF and DKIM have no enforcement |
| **MTA-STS** | Intercept mail in transit via a downgrade attack (STARTTLS stripping) |
| **TLS-RPT** | Silently lose mail to TLS failures with no notification |
| **BIMI** | Miss a signal to recipients that the sender is verified (requires DMARC `p=reject`) |

A domain without SPF and DMARC can be trivially spoofed — making it a prime vector for phishing attacks impersonating your organization. This tool makes it easy to spot these gaps.

---

## What is checked

| Record | DNS Name | Status logic |
|---|---|---|
| **A Record** | `<domain>` | Missing → WARN (mail can still work via MX) |
| **MX Record** | `<domain>` | Missing → CRITICAL |
| **PTR (Reverse DNS)** | per resolved IP | Missing per IP → WARN |
| **SPF** | `<domain>` TXT | Missing → CRITICAL; `+all` → CRITICAL; `~all`/`?all` → WARN; `-all` → OK |
| **DKIM** | `<selector>._domainkey.<domain>` | Missing → WARN (selector configurable) |
| **DMARC** | `_dmarc.<domain>` | Missing → CRITICAL; `p=none` → WARN; `p=quarantine`/`reject` → OK |
| **MTA-STS** | `_mta-sts.<domain>` | Missing → WARN; policy mode `enforce` → OK; `testing`/`none` → WARN |
| **TLS-RPT** | `_smtp._tls.<domain>` | Missing → WARN |
| **BIMI** | `<selector>._bimi.<domain>` | Missing → WARN (selector configurable) |

---

## Usage

```
./checkMailserver -domain <domain> [options]
```

### Flags

| Flag | Default | Description |
|---|---|---|
| `-domain` | *(required)* | The domain to audit |
| `-resolver` | system resolver | External DNS server to use, e.g. `8.8.8.8` or `1.1.1.1:53` |
| `-dkim-selector` | `default` | DKIM selector to look up |
| `-bimi-selector` | `default` | BIMI selector to look up |
| `-mta-sts-policy` | `false` | Also fetch and evaluate the MTA-STS policy file over HTTPS |

The `-resolver` flag is useful when your internal DNS returns different results than the public internet — for example if you use the same domain name internally and externally.

### Examples

Standard check:
```
./checkMailserver -domain example.com
```

Check against a public resolver (bypasses internal DNS):
```
./checkMailserver -domain example.com -resolver 8.8.8.8
```

Full audit with custom DKIM selector and MTA-STS policy fetch:
```
./checkMailserver -domain example.com -resolver 1.1.1.1 -dkim-selector mail -mta-sts-policy
```

### Example output

```
   OKAY      IP-ADDRESS: 203.0.113.42
   OKAY      MX Record: mail.example.com.
   WARN      ReverseAddr: no PTR record for 203.0.113.42
   OKAY      SPF Record: v=spf1 include:_spf.example.com -all
   OKAY      SPF Policy: -all (hard fail, strict)
   OKAY      DKIM Record: v=DKIM1; k=rsa; p=...
   OKAY      DMARC Record: v=DMARC1; p=reject; rua=mailto:reports@example.com
   OKAY      DMARC Policy: p=reject (enforced, strongest)
   OKAY      MTA-STS Record: v=STSv1; id=20240101T000000;
   OKAY      MTA-STS Policy: mode: enforce
   OKAY      TLS-RPT Record: v=TLSRPTv1; rua=mailto:sts-reports@example.com
   WARN      BIMI Record: no record found for selector "default"
```

---

## Build

```
go build .
```

## Development

```
go run . -domain example.com -resolver 8.8.8.8
```

---

## Recommended email security setup

For a fully protected domain the target configuration is:

1. **SPF** with `-all` (hard fail)
2. **DKIM** with a strong RSA or Ed25519 key, rotation every 6–12 months
3. **DMARC** with `p=reject` and a `rua=` reporting address to monitor alignment
4. **MTA-STS** in `enforce` mode with TLS-RPT enabled for transport security
5. **PTR record** matching the sending mail server's hostname (many servers check this)
6. **BIMI** once DMARC `p=reject` is in place (requires a VMC certificate for most providers)
