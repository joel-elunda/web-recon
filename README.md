# WebRecon

A single-file PowerShell script that audits a list of websites and prints every
security weakness it can detect from the outside, together with a concrete
exploitation recipe and a remediation hint.

Black-box, read-only, non-intrusive: WebRecon never writes on the target.

---

## Table of contents

1. [What it does](#what-it-does)
2. [Requirements](#requirements)
3. [Quick start](#quick-start)
4. [Parameters](#parameters)
5. [What gets checked](#what-gets-checked)
6. [Understanding the output](#understanding-the-output)
7. [The scoring model](#the-scoring-model)
8. [Exported reports](#exported-reports)
9. [How the script works internally](#how-the-script-works-internally)
10. [Extending the script](#extending-the-script)
11. [Limitations](#limitations)
12. [Legal note](#legal-note)

---

## What it does

`Invoke-WebRecon.ps1` accepts one or more URLs, performs a series of HTTP and TLS
checks against each of them, and renders the result as a colour-coded console
report. Every finding contains:

| Field | Meaning |
|---|---|
| Severity | `Critical`, `High`, `Medium`, `Low` or `Info` |
| Endpoint | The exact URL or host that triggered the finding |
| Evidence | The raw data observed (header value, status code, byte count…) |
| Impact | What an attacker gains from it |
| Exploit | A step-by-step recipe, with the actual commands to run |
| Fix | The remediation to apply |
| Reference | A documentation link |

At the end it prints a per-target summary table with severity counts, a 0–100
score and a letter grade, then optionally writes JSON / CSV / HTML reports.

---

## Requirements

- **Windows PowerShell 5.1** or **PowerShell 7+** (7+ recommended: faster,
  better TLS support, `-SkipCertificateCheck` works properly)
- .NET 4.5 or later
- Network access to the targets

No module needs to be installed. Only built-in .NET types are used
(`System.Net.Http`, `System.Net.Security`, `System.Net.Sockets`).

---

## Quick start

```powershell
# Single target
.\Invoke-WebRecon.ps1 -Sites 'https://example.com'

# Several targets at once
.\Invoke-WebRecon.ps1 example.com https://shop.example.org https://api.example.net

# Deep scan, HTML + JSON report in .\reports
.\Invoke-WebRecon.ps1 -Sites 'https://example.com' -DeepScan -Formats Json,Html -OutputPath .\reports

# Only show High and Critical in the console
.\Invoke-WebRecon.ps1 -Sites 'https://example.com' -SeverityThreshold High

# Keep going even with a broken certificate
.\Invoke-WebRecon.ps1 -Sites 'https://self-signed.lan' -SkipCertificateCheck
```

If PowerShell blocks the script, unblock it once:

```powershell
Unblock-File .\Invoke-WebRecon.ps1
```

Or bypass the policy for the current process:

```powershell
powershell -ExecutionPolicy Bypass -File .\Invoke-WebRecon.ps1 -Sites 'https://example.com'
```

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Sites` | `string[]` | *mandatory* | Targets. Positional, so `.\script.ps1 a b c` works. A missing scheme defaults to `https://`. |
| `-TimeoutSec` | `int` | `15` | Per-request timeout in seconds (1–300). |
| `-DeepScan` | `switch` | off | Enables the slower checks: sensitive files, admin panels, HTTP methods. |
| `-OutputPath` | `string` | current dir | Directory receiving the exported reports. Created if missing. |
| `-Formats` | `string[]` | `Json` | Any combination of `Json`, `Csv`, `Html`. |
| `-UserAgent` | `string` | WebRecon UA | User-Agent sent with every request. |
| `-SkipCertificateCheck` | `switch` | off | Continue scanning when the certificate is invalid. |
| `-SeverityThreshold` | `string` | `Info` | Hide findings below this severity in the console. |
| `-NoBanner` | `switch` | off | Suppress the ASCII banner. |

---

## What gets checked

### Always on

**Transport security**
- TLS certificate readable at all
- Certificate expired / not yet valid
- Certificate expiring within 30 or 15 days
- Certificate does not cover the requested hostname (SAN analysis)
- Self-signed certificate
- Weak signature algorithm (SHA-1 / MD5)
- Missing HTTP → HTTPS redirect
- Redirect that does not point to HTTPS
- Missing `Strict-Transport-Security`
- `max-age` shorter than 6 months, missing `includeSubDomains`
- Legacy TLS 1.0 and TLS 1.1 still negotiable

**Response headers**
- Missing `Content-Security-Policy`
- CSP containing `unsafe-inline` or `unsafe-eval`, or missing `frame-ancestors`
- Missing `X-Content-Type-Options: nosniff`
- Missing `X-Frame-Options` and no `frame-ancestors` → clickjacking
- Missing `Referrer-Policy`
- Missing `Permissions-Policy`
- Authenticated response cacheable by shared proxies

**Cookies**
- Missing `Secure`
- Missing `HttpOnly`
- Missing `SameSite`
- `SameSite=None` without `Secure`
- Session cookie without a `__Host-` / `__Secure-` prefix

**Information disclosure**
- `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator` banners, with
  severity raised when an exact version number is present

**CORS**
- Wildcard origin combined with credentials
- Arbitrary origin reflection with credentials
- Plain wildcard on a credentialed API

**Content analysis**
- Mixed content (HTTP subresources on an HTTPS page)
- External scripts without Subresource Integrity
- Form actions pointing to `http://`
- Directory listing enabled
- Password field without an explicit `autocomplete`

### Only with `-DeepScan`

**Sensitive files**
`/.git/HEAD`, `/.git/config`, `/.env`, `/.svn/entries`, `/web.config`,
`/phpinfo.php`, `/server-status`, `/swagger.json`, `/openapi.json`,
`/actuator/health`, `/.well-known/security.txt`, plus a list of backup and
editor leftovers (`index.php.bak`, `index.php~`, `.index.php.swp`, `backup.zip`,
`db.sql`, `composer.json`, `package.json`, `.htaccess`).

**Attack surface**
`/admin/`, `/administrator/`, `/wp-admin/`, `/wp-login.php`, `/phpmyadmin/`,
`/adminer.php`, `/manager/html`, `/login`, `/api/`, `/graphql`.

**HTTP methods**
`OPTIONS` enumeration and a direct `TRACE` probe.

---

## Understanding the output

Each finding is printed as a block:

```
  [   HIGH   ] Cookie 'PHPSESSID' is set without the Secure flag
              WEB-040  |  Cookies
              Endpoint   : https://example.com/
              Evidence   : Set-Cookie: PHPSESSID=abc123; Path=/; HttpOnly
              Impact     : The cookie is transmitted on plain HTTP, so any
                           network attacker can read and replay it.
              Exploit    : 1) Sit on the victim network. 2) Capture the cookie:
                           tcpdump -i wlan0 -A -s0 port 80 | grep -i set-cookie ...
              Fix        : Add `Secure` to the Set-Cookie for 'PHPSESSID'.
              Reference  : https://developer.mozilla.org/docs/Web/HTTP/Cookies
```

Severity colours: magenta = critical, red = high, yellow = medium,
cyan = low, dark grey = informational.

The header of each target block repeats the host and port. Findings are printed
live, as they are discovered, so the scan can be interrupted at any time and
still leave a readable partial report on screen.

---

## The scoring model

Each **unique** finding ID per host subtracts a fixed weight from a starting
score of 100:

| Severity | Weight |
|---|---|
| Critical | 20 |
| High | 10 |
| Medium | 4 |
| Low | 1.5 |
| Info | 0.25 |

Duplicates are collapsed by finding ID, so ten cookies missing the `Secure`
flag do not tank the score ten times.

The score is floored at 0 and mapped to a letter grade:

| Score | Grade |
|---|---|
| 90–100 | A |
| 80–89 | B |
| 70–79 | C |
| 55–69 | D |
| 40–54 | E |
| 0–39 | F |

The score is a prioritisation aid, not a certification. A site graded `A` can
still have a critical logic bug that no external scan can see.

---

## Exported reports

`-Formats` controls what is written. The filename always carries a UTC-ish
timestamp: `webrecon-20260101-143000.json`.

- **Json** — machine readable, includes the summary, the targets and every
  finding field. Suitable for feeding a dashboard or a CI step.
- **Csv** — one row per finding, same fields. Opens directly in Excel.
- **Html** — self-contained page with severity badges, suitable for emailing to
  a client or attaching to a ticket.

Reports are written **after** the console summary, so a long scan never blocks
the visible output.

---

## How the script works internally

The script is organised in clearly separated layers.

### 1. Parameter and global state

A `[CmdletBinding()]` `param` block declares the inputs. `$script:` variables
hold the shared state: the findings list (`$script:Findings`, a generic
`List[object]`), the scanned targets, and the lookup tables used to translate a
severity into a rank, a colour, a badge and a score weight.

### 2. Console UI helpers

`Write-Banner`, `Write-Rule`, `Write-Headline`, `Write-Status`, `Write-Field`
and `Write-Finding` isolate every `Write-Host` call. `Format-WrappedText` wraps
long evidence and exploitation strings on whitespace so nothing runs off the
side of the terminal.

### 3. Finding pipeline

`Add-Finding` is the single entry point for results. It builds a typed
`PSCustomObject`, appends it to the global list, and — if the severity passes
`-SeverityThreshold` — renders it immediately through `Write-Finding`. Every
check therefore only has to describe *what* it found; presentation is handled
once, in one place.

### 4. HTTP layer

`New-HttpClient` builds a `System.Net.Http.HttpClient` with the configured
timeout and User-Agent, and optionally installs a certificate-validation
callback that always returns `$true` (so an invalid certificate becomes a
finding instead of an error). On PowerShell 5.1, where the callback property
does not exist, it falls back to the global
`ServicePointManager.ServerCertificateValidationCallback`.

`Invoke-HttpProbe` sends a single request and returns a normalised object:
status code, reason phrase, a case-insensitive header dictionary, the raw
`Set-Cookie` values, the body (capped at 500 KB) and the elapsed time. It never
throws — network failures land in the `Error` property, so a dead endpoint does
not abort the whole scan.

Redirects are followed by default, except for the HTTP → HTTPS check, which
uses a dedicated non-redirecting client to observe the raw `301`/`302` and its
`Location` header.

### 5. Target resolution

`Resolve-Target` turns a user string into a `Uri` plus a small object carrying
the scheme, host, port and base URL. A missing scheme defaults to `https://`.

### 6. Check functions

Each check is a `Test-*` function that receives the target (and often the
baseline response) and emits findings through `Add-Finding`:

| Function | Scope |
|---|---|
| `Get-TlsCertificateInfo` | Reads the certificate via `SslStream` and extracts subject, issuer, validity, SANs and signature algorithm |
| `Test-TlsProtocolSupport` | Attempts a handshake pinned to a specific legacy protocol |
| `Test-CertificateHealth` | Expiry, hostname coverage, self-signing, weak signature |
| `Test-TransportHardening` | HTTP → HTTPS redirect and HSTS |
| `Test-LegacyTls` | TLS 1.0 / 1.1 acceptance |
| `Test-SecurityHeaders` | All response-header checks |
| `Test-CookieSecurity` | Parses `Set-Cookie` and audits the attributes |
| `Test-InformationDisclosure` | Technology banners |
| `Test-CorsPolicy` | Replays the request with a foreign `Origin` |
| `Test-ContentSecurity` | Regex analysis of the HTML body |
| `Test-SensitiveFiles` | Signature-verified probes of well-known paths |
| `Test-AdminPanels` | Status-code classification of admin URLs |
| `Test-HttpMethods` | `OPTIONS` / `TRACE` |

All checks are **read-only**. The most "aggressive" requests are `OPTIONS` and
`TRACE`; nothing is ever written on the target.

### 7. Reporting

`Get-SecurityScore` and `Get-Grade` implement the scoring model.
`Show-Summary` builds the per-target table. `Export-Reports` serialises the
findings list to JSON, CSV or HTML — the HTML variant escapes every value
through `ConvertTo-HtmlSafe` to avoid breaking the markup.

### 8. Entry point

The main loop resolves each target, registers it, and calls `Invoke-SiteScan`,
which runs the checks in a fixed order: baseline request, transport, headers and
cookies, CORS and content, then the deep-scan block when `-DeepScan` is set. A
`Write-Progress` bar tracks the overall position, and a `try/catch` around each
target makes sure one bad host cannot stop the scan.

---

## Extending the script

Adding a check takes three steps.

**1. Write the `Test-*` function.** Follow the existing signature convention:

```powershell
function Test-MyCheck {
    param([pscustomobject]$Target, [pscustomobject]$Response)

    $value = Get-HeaderValue -Headers $Response.Headers -Name 'X-My-Header'
    if (-not $value) {
        Add-Finding -Site $Target.Host -Id 'WEB-200' `
            -Title 'My header is missing' `
            -Severity 'Low' -Category 'Response Headers' `
            -Endpoint $Response.Url `
            -Evidence 'X-My-Header absent.' `
            -Impact 'Something bad happens.' `
            -Exploit 'curl -sI https://host/ | grep -i x-my-header' `
            -Remediation 'Add the header.' `
            -Reference 'https://example.org/'
    }
}
```

**2. Register it** inside `Invoke-SiteScan`, in the appropriate stage.

**3. Pick a unique `Id`.** The scoring model collapses duplicates by ID, so two
different checks must never share one. Use the `WEB-1xx` range for custom
checks to stay clear of the built-ins.

To add a sensitive-file probe, append an entry to the `$probes` array in
`Test-SensitiveFiles` — the loop handles the request, the signature match, the
evidence line and the `switch`-based exploitation text.

---

## Limitations

- **Black-box only.** Anything behind authentication, a WAF challenge or a
  JavaScript SPA is only partially visible.
- **No crawling.** Only the base page is analysed; sub-pages are not followed.
- **Regex HTML parsing.** Good enough for tag-level checks, not a real parser.
- **No active exploitation.** WebRecon describes the exploit, it does not run
  it. No `sqlmap`, no `nuclei`, no POST fuzzing.
- **SPA false negatives.** A site rendered entirely client-side may appear to
  have very few findings.
- **Header-based CORS only.** Preflight behaviour is inferred, not fully
  exercised.
- **Rate limiting.** With many targets and `-DeepScan`, requests are sequential
  and can take a while; raise `-TimeoutSec` on slow hosts.
- **PS 5.1 caveat.** `-SkipCertificateCheck` uses the global
  `ServicePointManager` callback on 5.1, which affects the whole process.

---

## Legal note

WebRecon sends ordinary HTTP requests. It is safe to run against a production
site, but **always get authorisation before scanning a host that is not yours** —
some WAFs count `OPTIONS`/`TRACE` probes and a `-DeepScan` run produces a few
dozen requests per target.

---

## Licence

MIT.