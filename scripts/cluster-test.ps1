<#
.SYNOPSIS
  Real-process scenarios for a three-node Sentinel cluster (works on Windows PowerShell 5.1 and PowerShell 7).

.DESCRIPTION
  Starts three real sentinel-node processes on this machine (loopback, real mTLS, real sled/Raft/audit files),
  drives them with real client certificates and checks what happens when nodes are killed, paused, sealed and
  restarted. Nothing is mocked. All data lives in a fresh run-<time> folder that is never deleted by this script.

  Scenarios:
    smoke    start-up log, nodes start sealed, unseal, write/read/list/delete across all nodes
    restart  kill -9 a follower, write past a snapshot while it is down, restart it: caught up by snapshot
    pause    suspend an unsealed follower, seal the whole cluster, trim the log past the seal, resume it:
             it must seal itself from the snapshot
    chaos    timed run of writes with random kills and pauses, then a cold restart of all three nodes and a
             check that every acknowledged write is on every node
    all      all of the above in this order (default)

  Needs: target\debug\sentinel-node.exe and sentinel-cli.exe (cargo build -p sentinel-node -p sentinel-cli) and
  an openssl.exe (the one that ships with Git for Windows is found automatically). The client certificates made
  by sentinel-cli are converted to .pfx files with openssl, because Windows PowerShell cannot load a PEM key.

  Run from anywhere:  powershell -ExecutionPolicy Bypass -File .\scripts\cluster-test.ps1
  The exit code is 0 only if every check passed.
#>
param(
    [ValidateSet('smoke', 'restart', 'pause', 'chaos', 'all')]
    [string]$Scenario = 'all',
    [string]$BinDir = '',
    [string]$OpenSsl = '',
    [string]$WorkDir = '',
    [int]$BasePort = 18441,
    [int]$ChaosSeconds = 60,
    [int]$Seed = 0
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

$script:IsWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
$script:ExeSuffix = ''
if ($script:IsWin) { $script:ExeSuffix = '.exe' }
$script:Results = New-Object System.Collections.ArrayList
$script:Nodes = @{}
$script:LeaderHint = 0
$script:PfxPass = 'sentinel'

# ---------------------------------------------------------------- the HTTPS helper (C# 5 compatible)
$csharp = @'
#pragma warning disable SYSLIB0057, SYSLIB0014
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class SentinelHttp
{
    private static readonly Dictionary<string, X509Certificate2> Certs = new Dictionary<string, X509Certificate2>();
    private static readonly object Gate = new object();
    private static X509Certificate2 Ca;

    // Reads a PEM certificate by hand: .NET Framework cannot be relied on to load PEM files itself.
    private static X509Certificate2 LoadPem(string path)
    {
        string text = File.ReadAllText(path);
        int a = text.IndexOf("-----BEGIN CERTIFICATE-----", StringComparison.Ordinal);
        int b = text.IndexOf("-----END CERTIFICATE-----", StringComparison.Ordinal);
        if (a < 0 || b < 0) throw new InvalidDataException("no certificate in " + path);
        string base64 = text.Substring(a + 27, b - (a + 27)).Replace("\r", "").Replace("\n", "").Trim();
        return new X509Certificate2(Convert.FromBase64String(base64));
    }

    public static void SetCa(string pemPath)
    {
        lock (Gate) { Ca = LoadPem(pemPath); }
    }

    private static X509Certificate2 LoadPfx(string path, string pass)
    {
        lock (Gate)
        {
            X509Certificate2 c;
            if (!Certs.TryGetValue(path, out c))
            {
                c = new X509Certificate2(path, pass);
                Certs[path] = c;
            }
            return c;
        }
    }

    public static void Cleanup()
    {
        lock (Gate)
        {
            foreach (KeyValuePair<string, X509Certificate2> kv in Certs) kv.Value.Dispose();
            Certs.Clear();
        }
    }

    // The server certificate must chain to OUR CA (the one given to SetCa) and to nothing else.
    // The host name is not checked: this is a loopback test harness.
    private static bool Validate(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors)
    {
        X509Certificate2 ca = Ca;
        if (cert == null || ca == null) return false;
        X509Chain c = new X509Chain();
        c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        c.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
        c.ChainPolicy.ExtraStore.Add(ca);
        bool built = c.Build(new X509Certificate2(cert));
        if (!built || c.ChainElements.Count < 2) return false;
        X509Certificate2 root = c.ChainElements[c.ChainElements.Count - 1].Certificate;
        return string.Equals(root.Thumbprint, ca.Thumbprint, StringComparison.OrdinalIgnoreCase);
    }

    // Returns { status, body, error }. Status 0 means no HTTP answer at all (see error).
    public static string[] Request(string method, string url, string pfxPath, string pfxPass,
                                   string contentType, byte[] body, int timeoutMs)
    {
        try
        {
            ServicePointManager.Expect100Continue = false;
            HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
            req.Method = method;
            req.Timeout = timeoutMs;
            req.ReadWriteTimeout = timeoutMs;
            req.KeepAlive = false;
            req.AllowAutoRedirect = false;
            req.Proxy = null;
            req.ServerCertificateValidationCallback = Validate;
            if (!string.IsNullOrEmpty(pfxPath)) req.ClientCertificates.Add(LoadPfx(pfxPath, pfxPass));
            if (body != null)
            {
                req.ContentType = contentType;
                req.ContentLength = body.Length;
                using (Stream s = req.GetRequestStream()) { s.Write(body, 0, body.Length); }
            }
            HttpWebResponse resp;
            try
            {
                resp = (HttpWebResponse)req.GetResponse();
            }
            catch (WebException we)
            {
                if (we.Response == null) return new string[] { "0", "", we.Status + ": " + we.Message };
                resp = (HttpWebResponse)we.Response;
            }
            using (resp)
            using (Stream rs = resp.GetResponseStream())
            using (MemoryStream ms = new MemoryStream())
            {
                rs.CopyTo(ms);
                return new string[] { ((int)resp.StatusCode).ToString(), Encoding.UTF8.GetString(ms.ToArray()), "" };
            }
        }
        catch (Exception e)
        {
            return new string[] { "0", "", e.GetType().Name + ": " + e.Message };
        }
    }
}
'@
if (-not ('SentinelHttp' -as [type])) {
    Add-Type -TypeDefinition $csharp -IgnoreWarnings
}
if ($script:IsWin -and -not ('SentinelProc' -as [type])) {
    Add-Type -IgnoreWarnings -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SentinelProc
{
    [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr handle);
    [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr handle);
}
'@
}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ---------------------------------------------------------------- small utilities
function P([string]$a, [string]$b) { return (Join-Path $a $b) }

function Log([string]$Text, [string]$Color = '') {
    if ($Color -ne '') { Write-Host $Text -ForegroundColor $Color } else { Write-Host $Text }
    if ($script:LogFile) { Add-Content -LiteralPath $script:LogFile -Value $Text }
}

function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    [void]$script:Results.Add([pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail })
    $tag = 'FAIL'; $color = 'Red'
    if ($Ok) { $tag = 'PASS'; $color = 'Green' }
    $line = '[{0}] {1}' -f $tag, $Name
    if ($Detail -ne '') { $line += '  (' + $Detail + ')' }
    Log $line $color
}

function Section([string]$Title) { Log ''; Log ('=== ' + $Title + ' ===') 'Cyan' }

function Quote-Arg([string]$a) {
    if ($a -eq '' -or $a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}

function Invoke-Native([string]$Exe, [string[]]$ArgList, $Stdin = $null, [string]$Cwd = '', [int]$TimeoutSec = 60) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = (($ArgList | ForEach-Object { Quote-Arg $_ }) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = ($null -ne $Stdin)
    if ($Cwd -ne '') { $psi.WorkingDirectory = $Cwd }
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $psi
    [void]$p.Start()
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    if ($null -ne $Stdin) { $p.StandardInput.Write([string]$Stdin); $p.StandardInput.Close() }
    if (-not $p.WaitForExit($TimeoutSec * 1000)) {
        try { $p.Kill() } catch { }
        return @{ Code = -1; Out = ''; Err = 'timed out' }
    }
    $p.WaitForExit()
    return @{ Code = $p.ExitCode; Out = $outTask.Result; Err = $errTask.Result }
}

function Wait-Until([scriptblock]$Cond, [int]$TimeoutSec) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (& $Cond) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Read-SharedText([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return '' }
    $fs = New-Object System.IO.FileStream($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $sr = New-Object System.IO.StreamReader($fs)
        return $sr.ReadToEnd()
    } finally { $fs.Dispose() }
}

function Write-Utf8NoBom([string]$Path, [string]$Text) {
    [IO.File]::WriteAllText($Path, $Text, (New-Object System.Text.UTF8Encoding($false)))
}

# ---------------------------------------------------------------- environment: CA, certificates, vault, configs
function Initialize-Environment {
    $script:Cli = P $script:Bin ('sentinel-cli' + $script:ExeSuffix)
    $script:NodeExe = P $script:Bin ('sentinel-node' + $script:ExeSuffix)
    foreach ($f in @($script:Cli, $script:NodeExe)) {
        if (-not (Test-Path -LiteralPath $f)) { throw "missing $f - run: cargo build -p sentinel-node -p sentinel-cli" }
    }
    $script:OpenSslPath = $OpenSsl
    if ($script:OpenSslPath -eq '') {
        $cands = @()
        if ($script:IsWin) {
            $cands += (P $env:ProgramFiles 'Git\usr\bin\openssl.exe')
            $cands += 'C:\Program Files\Git\usr\bin\openssl.exe'
        }
        foreach ($c in $cands) { if (Test-Path -LiteralPath $c) { $script:OpenSslPath = $c; break } }
        if ($script:OpenSslPath -eq '') {
            $g = Get-Command openssl -ErrorAction SilentlyContinue
            if ($g) { $script:OpenSslPath = $g.Source }
        }
    }
    if ($script:OpenSslPath -eq '') { throw 'openssl not found: pass -OpenSsl <path to openssl.exe>' }

    foreach ($i in 1..3) {
        $port = $BasePort + $i - 1
        $l = New-Object System.Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $l.Start(); $l.Stop() } catch { throw "port $port is already in use: pass -BasePort <free port>" }
    }

    New-Item -ItemType Directory -Force -Path $script:Run | Out-Null
    $script:PkiDir = P $script:Run 'pki'
    $script:VaultDir = P $script:Run 'vault'
    Log ('run folder: ' + $script:Run)

    $r = Invoke-Native $script:Cli @('pki', 'ca', '--out', 'ca') -Cwd $script:Run
    if ($r.Code -ne 0) { throw ('pki ca failed: ' + $r.Out + $r.Err) }
    foreach ($i in 1..3) {
        $r = Invoke-Native $script:Cli @('pki', 'issue', '--ca', 'ca', '--out', 'pki', '--cn', "node$i", '--kind', 'node', '--san', 'localhost', '--san', '127.0.0.1') -Cwd $script:Run
        if ($r.Code -ne 0) { throw ("pki issue node$i failed: " + $r.Out + $r.Err) }
    }
    foreach ($cn in @('alice-admin', 'app-writer', 'app-reader')) {
        $r = Invoke-Native $script:Cli @('pki', 'issue', '--ca', 'ca', '--out', 'pki', '--cn', $cn, '--kind', 'client') -Cwd $script:Run
        if ($r.Code -ne 0) { throw ("pki issue $cn failed: " + $r.Out + $r.Err) }
    }
    Copy-Item -LiteralPath (P (P $script:Run 'ca') 'ca.crt') -Destination (P $script:PkiDir 'ca.crt')

    # PEM -> PFX, with algorithms every Windows version can read (3DES + SHA1 instead of OpenSSL 3's AES default).
    foreach ($name in @('alice-admin', 'app-writer', 'app-reader', 'node1')) {
        $r = Invoke-Native $script:OpenSslPath @('pkcs12', '-export',
            '-inkey', (P $script:PkiDir "$name.key"), '-in', (P $script:PkiDir "$name.crt"),
            '-out', (P $script:PkiDir "$name.pfx"), '-passout', ('pass:' + $script:PfxPass),
            '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1')
        if ($r.Code -ne 0) { throw ("openssl pkcs12 for $name failed: " + $r.Out + $r.Err) }
    }
    [SentinelHttp]::SetCa((P $script:PkiDir 'ca.crt'))

    $r = Invoke-Native $script:Cli @('init', '--holder', 'alice', '--holder', 'bob', '--holder', 'carol', '--threshold', '2', '--out', 'vault', '--format', 'plain') -Cwd $script:Run
    if ($r.Code -ne 0) { throw ('init failed: ' + $r.Out + $r.Err) }

    foreach ($i in 1..3) {
        $dir = P $script:Run "node$i"
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        $peers = @()
        foreach ($j in 1..3) { if ($j -ne $i) { $peers += ("'{0}=https://127.0.0.1:{1}'" -f $j, ($BasePort + $j - 1)) } }
        $toml = @(
            "node_id = $i",
            "api_bind_addr = '127.0.0.1:$($BasePort + $i - 1)'",
            "storage_path = '$(P $dir 'data')'",
            "tls_cert_path = '$(P $script:PkiDir "node$i.crt")'",
            "tls_key_path = '$(P $script:PkiDir "node$i.key")'",
            "ca_cert_path = '$(P $script:PkiDir 'ca.crt')'",
            "canary_file = '$(P $script:VaultDir 'canary.bin')'",
            'unseal_threshold = 2',
            "admin_cns = ['alice-admin']",
            "writer_cns = ['app-writer']",
            "reader_cns = ['app-reader']",
            ('peers = [' + ($peers -join ', ') + ']'),
            "peer_cns = ['node1', 'node2', 'node3']",
            'snapshot_threshold = 10',
            'anomaly_min_burst = 100000'
        ) -join "`n"
        Write-Utf8NoBom (P $dir '.env.toml') ($toml + "`n")
        $script:Nodes[$i] = @{
            Index = $i; Port = ($BasePort + $i - 1); Dir = $dir; Proc = $null; Paused = $false; Starts = 0
            Audit = ((P $dir 'data') + '.audit.jsonl')
        }
    }
}

# ---------------------------------------------------------------- nodes
function Test-Alive([int]$i) {
    $n = $script:Nodes[$i]
    return (($null -ne $n.Proc) -and (-not $n.Proc.HasExited))
}
function Test-Reachable([int]$i) { return ((Test-Alive $i) -and (-not $script:Nodes[$i].Paused)) }

function Start-Node([int]$i) {
    $n = $script:Nodes[$i]
    $n.Starts = $n.Starts + 1
    $sp = @{
        FilePath               = $script:NodeExe
        WorkingDirectory       = $n.Dir
        RedirectStandardOutput = (P $n.Dir ('out-{0}.log' -f $n.Starts))
        RedirectStandardError  = (P $n.Dir ('err-{0}.log' -f $n.Starts))
        PassThru               = $true
    }
    if ($script:IsWin) { $sp['WindowStyle'] = 'Hidden' }
    $n.Proc = Start-Process @sp
    $n.Paused = $false
}

function Stop-NodeHard([int]$i) {
    $n = $script:Nodes[$i]
    if (Test-Alive $i) {
        Stop-Process -Id $n.Proc.Id -Force
        [void]$n.Proc.WaitForExit(15000)
    }
    $n.Paused = $false
}

function Suspend-Node([int]$i) {
    $n = $script:Nodes[$i]
    if ($script:IsWin) { [void][SentinelProc]::NtSuspendProcess($n.Proc.Handle) }
    else { [void](Invoke-Native '/bin/kill' @('-STOP', [string]$n.Proc.Id)) }
    $n.Paused = $true
}

function Resume-Node([int]$i) {
    $n = $script:Nodes[$i]
    if ($script:IsWin) { [void][SentinelProc]::NtResumeProcess($n.Proc.Handle) }
    else { [void](Invoke-Native '/bin/kill' @('-CONT', [string]$n.Proc.Id)) }
    $n.Paused = $false
}

function Get-NodeLogText([int]$i) {
    $text = ''
    foreach ($f in (Get-ChildItem -LiteralPath $script:Nodes[$i].Dir -Filter '*.log' | Sort-Object Name)) {
        $text += (Read-SharedText $f.FullName) + "`n"
    }
    return $text
}

# ---------------------------------------------------------------- talking to a node
function Invoke-Sentinel([int]$Node, [string]$Method, [string]$Path, [string]$Identity = 'alice-admin',
                         $Body = $null, [string]$ContentType = 'application/octet-stream', [int]$TimeoutMs = 4000) {
    $url = 'https://127.0.0.1:{0}{1}' -f $script:Nodes[$Node].Port, $Path
    $bytes = $null
    if ($null -ne $Body) { $bytes = [Text.Encoding]::UTF8.GetBytes([string]$Body) }
    $r = [SentinelHttp]::Request($Method, $url, (P $script:PkiDir "$Identity.pfx"), $script:PfxPass, $ContentType, $bytes, $TimeoutMs)
    return @{ Status = [int]$r[0]; Body = $r[1]; Error = $r[2] }
}

# The key list is a JSON array of plain strings. Windows PowerShell 5.1 does not unroll a top-level array from
# ConvertFrom-Json, so it is read with a regex instead, which behaves the same on every version.
function Get-KeyList([int]$i, [int]$TimeoutMs = 8000) {
    $r = Invoke-Sentinel $i 'GET' '/secrets' 'app-reader' $null 'application/json' $TimeoutMs
    if ($r.Status -ne 200) { return $null }
    $keys = New-Object System.Collections.ArrayList
    foreach ($m in [regex]::Matches($r.Body, '"([^"\\]*)"')) { [void]$keys.Add($m.Groups[1].Value) }
    return , $keys.ToArray()
}

function Get-NodeStatus([int]$i) {
    $r = Invoke-Sentinel $i 'GET' '/cluster/status' 'alice-admin' $null 'application/json' 2500
    if ($r.Status -eq 200) { return ($r.Body | ConvertFrom-Json) }
    return $null
}

function Get-Ready([int]$i) {
    return (Invoke-Sentinel $i 'GET' '/readyz' 'alice-admin' $null 'application/json' 2500).Status
}

# 1 = sealed, 0 = unsealed, $null = could not be read. /readyz alone cannot say this: it is also 503 when the
# audit log cannot be written or the Raft actor does not answer.
function Get-Sealed([int]$i) {
    $v = Get-Metric $i 'sentinel_sealed'
    if ($null -eq $v) { return $null }
    return [int]$v
}

function Get-ReadyDetail([int]$i) {
    $r = Invoke-Sentinel $i 'GET' '/readyz' 'alice-admin' $null 'application/json' 2500
    return ('readyz {0} {1} {2}' -f $r.Status, $r.Body, $r.Error).Trim()
}

function Get-Metric([int]$i, [string]$Name) {
    $r = Invoke-Sentinel $i 'GET' '/metrics' 'alice-admin' $null 'application/json' 3000
    if ($r.Status -ne 200) { return $null }
    $m = [regex]::Match($r.Body, '(?m)^' + [regex]::Escape($Name) + '(\{[^}]*\})?\s+(-?[0-9.eE+-]+)\s*$')
    if (-not $m.Success) { return $null }
    return [double]::Parse($m.Groups[2].Value, [Globalization.CultureInfo]::InvariantCulture)
}

function Find-Leader {
    $best = 0; $bestTerm = -1
    foreach ($i in ($script:Nodes.Keys | Sort-Object)) {
        if (-not (Test-Reachable $i)) { continue }
        $s = Get-NodeStatus $i
        if (($null -ne $s) -and ($s.role -eq 'Leader') -and ($s.term -gt $bestTerm)) { $best = $i; $bestTerm = $s.term }
    }
    return $best
}

function Put-Secret([string]$Key, [string]$Value) {
    for ($attempt = 0; $attempt -lt 2; $attempt++) {
        if (($script:LeaderHint -eq 0) -or (-not (Test-Reachable $script:LeaderHint))) { $script:LeaderHint = Find-Leader }
        if ($script:LeaderHint -eq 0) { Start-Sleep -Milliseconds 150; return $false }
        $r = Invoke-Sentinel $script:LeaderHint 'PUT' "/secrets/$Key" 'app-writer' $Value 'application/octet-stream' 8000
        if ($r.Status -eq 200) { return $true }
        $script:LeaderHint = 0
        if ($r.Status -ne 421) { Start-Sleep -Milliseconds 100; return $false }
    }
    return $false
}

function Put-SecretRetry([string]$Key, [string]$Value, [int]$TimeoutSec = 20) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (Put-Secret $Key $Value) { return $true }
    }
    return $false
}

function Remove-SecretRetry([string]$Key, [int]$TimeoutSec = 20) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
        if (($script:LeaderHint -eq 0) -or (-not (Test-Reachable $script:LeaderHint))) { $script:LeaderHint = Find-Leader }
        if ($script:LeaderHint -ne 0) {
            $r = Invoke-Sentinel $script:LeaderHint 'DELETE' "/secrets/$Key" 'app-writer' $null 'application/octet-stream' 8000
            if (($r.Status -eq 200) -or ($r.Status -eq 204)) { return $true }
            $script:LeaderHint = 0
        }
        Start-Sleep -Milliseconds 150
    }
    return $false
}

# Polls until every expected key reads back right on the node. $Expected maps key -> value; $Absent are keys that must be 404.
function Test-NodeHasKeys([int]$i, [hashtable]$Expected, [string[]]$Absent = @(), [int]$TimeoutSec = 25) {
    $pending = New-Object System.Collections.ArrayList
    foreach ($k in $Expected.Keys) { [void]$pending.Add(@{ Key = $k; Want = $Expected[$k] }) }
    foreach ($k in $Absent) { [void]$pending.Add(@{ Key = $k; Want = $null }) }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $sample = ''
    while ($true) {
        $still = New-Object System.Collections.ArrayList
        foreach ($item in $pending) {
            $r = Invoke-Sentinel $i 'GET' ('/secrets/' + $item.Key) 'app-reader' $null 'application/octet-stream' 4000
            $ok = $false
            if ($null -eq $item.Want) { $ok = ($r.Status -eq 404) }
            else { $ok = (($r.Status -eq 200) -and ($r.Body -ceq $item.Want)) }
            if (-not $ok) {
                [void]$still.Add($item)
                $sample = 'key {0}: http {1} {2}' -f $item.Key, $r.Status, $r.Error
            }
        }
        $pending = $still
        if ($pending.Count -eq 0) { return @{ Ok = $true; Bad = 0; Sample = '' } }
        if ($sw.Elapsed.TotalSeconds -ge $TimeoutSec) { return @{ Ok = $false; Bad = $pending.Count; Sample = $sample } }
        Start-Sleep -Milliseconds 400
    }
}

function Unseal-Node([int]$i) {
    $port = $script:Nodes[$i].Port
    foreach ($holder in @('alice', 'bob')) {
        $share = [IO.File]::ReadAllText((P $script:VaultDir "share-$holder.hex"))
        $r = Invoke-Native $script:Cli @('submit-share', '--node', "https://127.0.0.1:$port",
            '--cert', (P $script:PkiDir 'alice-admin.crt'), '--key', (P $script:PkiDir 'alice-admin.key'),
            '--ca', (P $script:PkiDir 'ca.crt'), '--holder', $holder) $share
        if ($r.Code -ne 0) { return $false }
    }
    return (Wait-Until { (Get-Ready $i) -eq 200 } 10)
}

function Test-AuditChain([int]$i) {
    $f = $script:Nodes[$i].Audit
    $r = Invoke-Native $script:Cli @('verify', $f)
    if ($r.Code -eq 0) { return @{ Ok = $true; Note = ($r.Out.Trim().Split("`n") | Select-Object -Last 1).Trim() } }
    if ((($r.Out + $r.Err) -match 'INCOMPLETE FINAL RECORD')) {
        $r2 = Invoke-Native $script:Cli @('verify', $f, '--allow-torn-tail')
        if ($r2.Code -eq 0) { return @{ Ok = $true; Note = 'chain OK; an unfinished last record was ignored' } }
    }
    return @{ Ok = $false; Note = (($r.Out + $r.Err).Trim()) }
}

# Starts every node that is not running, waits for them to answer, unseals the sealed ones, waits for a leader.
function Ensure-ClusterReady([bool]$ReportSealedStart = $false) {
    foreach ($i in 1..3) {
        if ($script:Nodes[$i].Paused) { Resume-Node $i }
        if (-not (Test-Alive $i)) { Start-Node $i }
    }
    foreach ($i in 1..3) {
        $up = Wait-Until { $null -ne (Get-NodeStatus $i) } 30
        if (-not $up) { throw "node $i does not answer on port $($script:Nodes[$i].Port) - see $($script:Nodes[$i].Dir)" }
    }
    if ($ReportSealedStart) {
        $allSealed = $true
        foreach ($i in 1..3) { if (((Get-Sealed $i) -ne 1) -or ((Get-Ready $i) -ne 503)) { $allSealed = $false } }
        Check 'a freshly started node is sealed (sentinel_sealed 1, readyz 503) on all three nodes' $allSealed
    }
    foreach ($i in 1..3) {
        if ((Get-Ready $i) -ne 200) {
            if (-not (Unseal-Node $i)) { throw "could not unseal node $i" }
        }
    }
    $script:LeaderHint = 0
    if (-not (Wait-Until { (Find-Leader) -ne 0 } 30)) { throw 'no leader elected' }
}

function Pick-Follower([int]$Leader) {
    foreach ($i in 1..3) { if ($i -ne $Leader) { return $i } }
    return 0
}

# ---------------------------------------------------------------- scenarios
function Scenario-Smoke {
    Section 'smoke: start-up, unseal, write / read / list / delete'
    Ensure-ClusterReady $true
    $leader = Find-Leader
    $leaders = 0
    foreach ($i in 1..3) { $s = Get-NodeStatus $i; if ($s.role -eq 'Leader') { $leaders++ } }
    Check 'exactly one leader' ($leaders -eq 1) "leader is node $leader"

    $withLine = 0
    foreach ($i in 1..3) { if ((Get-NodeLogText $i) -match 'snapshots on') { $withLine++ } }
    Check 'start-up log shows "snapshots on" with RUST_LOG unset (the info default, phase 20c)' ($withLine -eq 3)

    $exp = @{}
    foreach ($k in 1..5) {
        $key = 'smoke-{0}' -f $k; $val = 'smoke-value-{0}-{1}' -f $k, ([guid]::NewGuid().ToString('N'))
        if (Put-SecretRetry $key $val) { $exp[$key] = $val }
    }
    Check 'five writes acknowledged' ($exp.Count -eq 5)
    foreach ($i in 1..3) {
        $t = Test-NodeHasKeys $i $exp @('smoke-missing')
        Check "node $i returns all five values and 404 for a missing key" $t.Ok $t.Sample
    }
    $listed = Get-KeyList 1 4000
    $allListed = ($null -ne $listed)
    if ($allListed) { foreach ($k in $exp.Keys) { if ($listed -notcontains $k) { $allListed = $false } } }
    $count = 0
    if ($null -ne $listed) { $count = $listed.Count }
    Check 'list shows the written keys' $allListed "$count keys listed"
    $del = Remove-SecretRetry 'smoke-1'
    $gone = $true
    foreach ($i in 1..3) { $t = Test-NodeHasKeys $i @{} @('smoke-1') 15; if (-not $t.Ok) { $gone = $false } }
    Check 'a deleted key is 404 on every node' ($del -and $gone)
    $w = Invoke-Sentinel $script:LeaderHint 'PUT' '/secrets/smoke-denied' 'app-reader' 'x' 'application/octet-stream' 4000
    Check 'a reader certificate cannot write (authorization is enforced)' ($w.Status -eq 403) "http $($w.Status)"
}

function Scenario-Restart {
    Section 'restart: kill a follower, write past a snapshot, restart it'
    Ensure-ClusterReady
    $leader = Find-Leader
    $f = Pick-Follower $leader
    Log "leader is node $leader, victim is node $f"
    $exp = @{}
    foreach ($k in 1..25) {
        $key = 'rs-a-{0:D2}' -f $k; $val = 'a-{0}-{1}' -f $k, ([guid]::NewGuid().ToString('N'))
        if (Put-SecretRetry $key $val) { $exp[$key] = $val }
    }
    Check '25 writes acknowledged before the kill' ($exp.Count -eq 25)
    $ls = Get-NodeStatus $leader
    [void](Wait-Until { (Get-NodeStatus $f).applied_index -ge $ls.applied_index } 20)
    $appliedBefore = (Get-NodeStatus $f).applied_index
    $installedBefore = Get-Metric $f 'sentinel_raft_snapshots_installed_total'
    Stop-NodeHard $f
    Log "node $f killed with it applied up to index $appliedBefore"

    $more = 0
    foreach ($k in 1..40) {
        $key = 'rs-b-{0:D2}' -f $k; $val = 'b-{0}-{1}' -f $k, ([guid]::NewGuid().ToString('N'))
        if (Put-SecretRetry $key $val) { $exp[$key] = $val; $more++ }
    }
    $absent = @('rs-a-01', 'rs-a-02')
    $dels = 0
    foreach ($k in $absent) { if (Remove-SecretRetry $k) { $dels++ }; $exp.Remove($k) }
    Check '40 writes and 2 deletes acknowledged while the node was down' (($more -eq 40) -and ($dels -eq 2))
    $trimmed = Wait-Until { (Get-Metric $leader 'sentinel_raft_snapshot_index') -gt $appliedBefore } 30
    Check 'the survivors trimmed their log past where the dead node stopped' $trimmed

    Start-Node $f
    Check 'the killed node answers again after a restart' (Wait-Until { $null -ne (Get-NodeStatus $f) } 30)
    Check 'a restarted node comes back sealed (sentinel_sealed 1)' ((Get-Sealed $f) -eq 1) (Get-ReadyDetail $f)
    $caught = Wait-Until { (Get-NodeStatus $f).applied_index -ge (Get-NodeStatus $leader).applied_index } 30
    Check 'it catches up while sealed' $caught
    $installedAfter = Get-Metric $f 'sentinel_raft_snapshots_installed_total'
    Check 'it was caught up by a snapshot (installed counter went up)' (($null -ne $installedAfter) -and ($installedAfter -ge 1)) "installed $installedBefore -> $installedAfter"
    # Leadership can change while the follower is down (seen in repeated runs on a loaded one-core machine),
    # so the node that sent the snapshot is whichever one led when the follower caught up: ask all of them.
    $sentTotal = 0
    $sentBy = @()
    foreach ($i in 1..3) {
        $v = Get-Metric $i 'sentinel_raft_snapshots_sent_total'
        if ($null -eq $v) { $v = 0 }
        $sentTotal += $v
        $sentBy += "node $i sent $v"
    }
    Check 'a surviving node reports having sent a snapshot' ($sentTotal -ge 1) ($sentBy -join ', ')
    Check 'it can be unsealed again' (Unseal-Node $f)
    $t = Test-NodeHasKeys $f $exp $absent
    Check 'the restarted node serves every right value and 404 for the deleted keys' $t.Ok $t.Sample
    $audit = Read-SharedText $script:Nodes[$f].Audit
    Check 'its audit log records the restore from a snapshot' ($audit -match 'state restored from a snapshot')
}

function Scenario-Pause {
    Section 'pause: suspend an unsealed follower, seal the cluster, trim past the seal, resume'
    Ensure-ClusterReady
    $leader = Find-Leader
    $f = Pick-Follower $leader
    $others = @()
    foreach ($i in 1..3) { if ($i -ne $f) { $others += $i } }
    Log "leader is node $leader, victim is node $f"
    $exp = @{}
    foreach ($k in 1..5) {
        $key = 'ps-pre-{0}' -f $k; $val = 'pre-{0}-{1}' -f $k, ([guid]::NewGuid().ToString('N'))
        if (Put-SecretRetry $key $val) { $exp[$key] = $val }
    }
    $ls = Get-NodeStatus $leader
    [void](Wait-Until { (Get-NodeStatus $f).applied_index -ge $ls.applied_index } 20)
    Check 'the victim is unsealed before it is paused (sentinel_sealed 0, readyz 200)' (((Get-Sealed $f) -eq 0) -and ((Get-Ready $f) -eq 200))
    $appliedBefore = (Get-NodeStatus $f).applied_index
    $installedBefore = Get-Metric $f 'sentinel_raft_snapshots_installed_total'
    Suspend-Node $f
    Log "node $f suspended at applied index $appliedBefore"

    $r = Invoke-Sentinel $leader 'POST' '/raft/seal-request' 'node1' '{"reason":"cluster-test: seal while a node is paused"}' 'application/json' 6000
    Check 'a node certificate can ask the leader to seal the whole cluster (202)' ($r.Status -eq 202) "http $($r.Status) $($r.Error)"
    $sealed = Wait-Until { ((Get-Sealed $others[0]) -eq 1) -and ((Get-Sealed $others[1]) -eq 1) } 15
    Check 'both running nodes sealed (sentinel_sealed 1)' $sealed
    $un = (Unseal-Node $others[0]) -and (Unseal-Node $others[1])
    Check 'the two running nodes were unsealed again' $un
    $script:LeaderHint = 0
    [void](Wait-Until { (Find-Leader) -ne 0 } 20)

    $more = 0
    foreach ($k in 1..40) {
        $key = 'ps-post-{0:D2}' -f $k; $val = 'post-{0}-{1}' -f $k, ([guid]::NewGuid().ToString('N'))
        if (Put-SecretRetry $key $val) { $exp[$key] = $val; $more++ }
    }
    Check '40 writes acknowledged while the node was paused' ($more -eq 40)
    $leader = Find-Leader
    $trimmed = Wait-Until { (Get-Metric $leader 'sentinel_raft_snapshot_index') -gt $appliedBefore } 30
    Check 'the running nodes trimmed their log past the paused node' $trimmed

    Resume-Node $f
    Log "node $f resumed"
    $caught = Wait-Until { (Get-NodeStatus $f).applied_index -ge (Get-NodeStatus $leader).applied_index } 40
    Check 'the resumed node catches up' $caught
    $installedAfter = Get-Metric $f 'sentinel_raft_snapshots_installed_total'
    Check 'it was caught up by a snapshot' (($null -ne $installedAfter) -and ($installedAfter -gt $installedBefore)) "installed $installedBefore -> $installedAfter"
    $selfSealed = Get-Sealed $f
    Check 'it SEALED ITSELF although it never saw the seal command (sentinel_sealed 1)' ($selfSealed -eq 1) ('sentinel_sealed=' + $selfSealed + '; ' + (Get-ReadyDetail $f))
    $audit = Read-SharedText $script:Nodes[$f].Audit
    Check 'its audit log explains it: the snapshot covers a cluster-wide seal' ($audit -match 'covers a cluster-wide seal')
    Check 'it can be unsealed again' (Unseal-Node $f)
    $t = Test-NodeHasKeys $f $exp
    Check 'the resumed node serves every right value' $t.Ok $t.Sample
}

function Scenario-Chaos {
    Section "chaos: $ChaosSeconds seconds of writes with random kills and pauses, then a cold restart"
    Ensure-ClusterReady
    Log "random seed for the fault schedule: $script:SeedValue"
    $rng = New-Object System.Random $script:SeedValue
    $acked = @{}
    $attempted = 0; $kills = 0; $pauses = 0
    $fault = $null
    $nextFaultAt = 3.0
    $n = 0
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $ChaosSeconds) {
        $t = $sw.Elapsed.TotalSeconds
        if (($null -eq $fault) -and ($t -ge $nextFaultAt)) {
            $victim = 1 + $rng.Next(0, 3)
            if ($rng.Next(0, 3) -lt 2) {
                Stop-NodeHard $victim; $kills++
                $fault = @{ Kind = 'kill'; Node = $victim; EndAt = $t + 1.5 + ($rng.NextDouble() * 2.5) }
            } else {
                Suspend-Node $victim; $pauses++
                $fault = @{ Kind = 'pause'; Node = $victim; EndAt = $t + 3.0 }
            }
            if ($script:LeaderHint -eq $victim) { $script:LeaderHint = 0 }
            Log ('  t={0,5:N1}s  {1} node {2}' -f $t, $fault.Kind, $victim)
        } elseif (($null -ne $fault) -and ($t -ge $fault.EndAt)) {
            if ($fault.Kind -eq 'kill') {
                Start-Node $fault.Node
                if (Wait-Until { $null -ne (Get-NodeStatus $fault.Node) } 30) { [void](Unseal-Node $fault.Node) }
            } else {
                Resume-Node $fault.Node
            }
            Log ('  t={0,5:N1}s  {1} over, node {2} is back' -f $sw.Elapsed.TotalSeconds, $fault.Kind, $fault.Node)
            $fault = $null
            $nextFaultAt = $sw.Elapsed.TotalSeconds + 1.0 + ($rng.NextDouble() * 3.0)
        }
        $n++
        $key = 'chaos-{0:D5}' -f $n
        $val = 'v{0}-{1}' -f $n, ([guid]::NewGuid().ToString('N'))
        $attempted++
        if (Put-Secret $key $val) { $acked[$key] = $val }
    }
    if ($null -ne $fault) {
        if ($fault.Kind -eq 'kill') {
            Start-Node $fault.Node
            if (Wait-Until { $null -ne (Get-NodeStatus $fault.Node) } 30) { [void](Unseal-Node $fault.Node) }
        } else { Resume-Node $fault.Node }
    }
    Log "chaos finished: $attempted attempted, $($acked.Count) acknowledged, $kills kills, $pauses pauses"
    Check 'writes were acknowledged during the chaos' ($acked.Count -gt 0) "$($acked.Count) of $attempted"

    Ensure-ClusterReady
    $term = (Get-NodeStatus (Find-Leader)).term
    Log "leadership term after the chaos: $term"

    Log 'cold restart: killing all three nodes, then starting them from disk'
    foreach ($i in 1..3) { Stop-NodeHard $i }
    foreach ($i in 1..3) { Start-Node $i }
    $back = $true
    foreach ($i in 1..3) { if (-not (Wait-Until { $null -ne (Get-NodeStatus $i) } 40)) { $back = $false } }
    Check 'all three nodes start again from their files' $back
    $unsealed = $true
    foreach ($i in 1..3) { if (-not (Unseal-Node $i)) { $unsealed = $false } }
    Check 'all three can be unsealed again' $unsealed
    $script:LeaderHint = 0
    Check 'a leader is elected after the cold restart' (Wait-Until { (Find-Leader) -ne 0 } 30)

    $marker = 'chaos-marker'; $markerVal = 'm-' + [guid]::NewGuid().ToString('N')
    $markerOk = Put-SecretRetry $marker $markerVal 30
    Check 'the cluster accepts a write after the cold restart' $markerOk
    $acked[$marker] = $markerVal

    $allOk = $true; $detail = ''
    foreach ($i in 1..3) {
        $t = Test-NodeHasKeys $i $acked @() 60
        Log ('  node {0}: {1} acknowledged writes checked, {2} wrong or missing' -f $i, $acked.Count, $t.Bad)
        if (-not $t.Ok) { $allOk = $false; $detail = $t.Sample }
    }
    Check "every acknowledged write ($($acked.Count)) is present with the right value on all three nodes" $allOk $detail

    $sets = @()
    foreach ($i in 1..3) {
        $keys = Get-KeyList $i 15000
        if ($null -eq $keys) { $keys = @() }
        $keys = @($keys | Sort-Object -CaseSensitive)
        $sets += , ($keys -join ',')
        Log ('  node {0}: {1} keys' -f $i, $keys.Count)
    }
    Check 'all three nodes hold exactly the same set of keys' (($sets[0] -ceq $sets[1]) -and ($sets[1] -ceq $sets[2]) -and ($sets[0] -ne ''))
}

# ---------------------------------------------------------------- main
$script:SeedValue = $Seed
if ($script:SeedValue -eq 0) { $script:SeedValue = [Environment]::TickCount }
if ($BinDir -ne '') { $script:Bin = $BinDir }
else { $script:Bin = P (P (Split-Path -Parent $PSScriptRoot) 'target') 'debug' }
$base = $WorkDir
if ($base -eq '') { $base = P ([IO.Path]::GetTempPath()) 'sentinel-cluster-test' }
$script:Run = P $base ('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$script:LogFile = $null
$exitCode = 1
try {
    Initialize-Environment
    $script:LogFile = P $script:Run 'harness.log'
    Log ('Sentinel cluster test  ' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
    Log ('PowerShell {0} on {1}' -f $PSVersionTable.PSVersion, [Environment]::OSVersion.VersionString)
    Log ('binaries: ' + $script:Bin)
    foreach ($f in @($script:NodeExe, $script:Cli)) {
        Log ('  {0}  sha256 {1}' -f (Split-Path -Leaf $f), (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.Substring(0, 12).ToLower())
    }
    Remove-Item Env:RUST_LOG -ErrorAction SilentlyContinue
    $plan = @($Scenario)
    if ($Scenario -eq 'all') { $plan = @('smoke', 'restart', 'pause', 'chaos') }
    foreach ($s in $plan) {
        try {
            switch ($s) {
                'smoke'   { Scenario-Smoke }
                'restart' { Scenario-Restart }
                'pause'   { Scenario-Pause }
                'chaos'   { Scenario-Chaos }
            }
        } catch {
            Check "scenario $s ran to the end" $false $_.Exception.Message
        }
    }

    Section 'final checks'
    foreach ($i in 1..3) {
        if (Test-Alive $i) {
            $a = Test-AuditChain $i
            Check "node $i audit hash chain verifies" $a.Ok $a.Note
        }
    }
    $panics = 0
    foreach ($i in 1..3) { if ((Get-NodeLogText $i) -match 'panicked at') { $panics++ } }
    Check 'no node logged a panic' ($panics -eq 0)
} catch {
    Log ('ABORTED: ' + $_.Exception.Message) 'Red'
    Check 'the harness itself ran' $false $_.Exception.Message
} finally {
    foreach ($i in $script:Nodes.Keys) {
        try { if (Test-Alive $i) { Stop-Process -Id $script:Nodes[$i].Proc.Id -Force } } catch { }
    }
    try { [SentinelHttp]::Cleanup() } catch { }
}

$failed = @($script:Results | Where-Object { -not $_.Ok })
Log ''
Log ('{0} checks, {1} passed, {2} failed' -f $script:Results.Count, ($script:Results.Count - $failed.Count), $failed.Count) $(if ($failed.Count -eq 0) { 'Green' } else { 'Red' })
foreach ($f in $failed) { Log ('  FAILED: ' + $f.Name + '  ' + $f.Detail) 'Red' }
Log ('everything is kept in ' + $script:Run)
if (($script:Results.Count -gt 0) -and ($failed.Count -eq 0)) { exit 0 }
exit 1
