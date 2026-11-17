# ============================================================
#  net_monitor.ps1  -  мой сетевой слушатель инт сети но не старее в пов (PowerShell 5.1+)
#  Поместить в свою папку на раб столе (next to config\ and *.bat).
#  Start: start_monitor.bat   Stop: stop.bat   Report: report.bat
#  Сат в реальном времени ввывод-ся в репорт бат
#  To mark a felt outage: create an empty file named MARK in the folder.
# ============================================================

$ErrorActionPreference = 'SilentlyContinue'
$base = Split-Path -Parent $MyInvocation.MyCommand.Path
$iniPath = Join-Path $base 'config\monitor.ini'

$cfg = @{
  INTERVAL_SEC   = 2
  ENABLE_DNS     = 1
  ENABLE_INET    = 1
  ENABLE_GW      = 1
  ENABLE_ADAPTER = 1
  DNS_EXT        = '1.1.1.1'
  DNS_NAME       = 'ya.ru'
  INET_HOST      = '1.1.1.1'
  INET_PORT      = 443
  GW_IP          = ''
  TCP_SLOW_MS    = 200
  DNS_SLOW_MS    = 500
  TIMEOUT_MS     = 4000
}

# ---- read ini tolerantly (works with UTF-8 / UTF-16 / ANSI / BOM) ----
if (Test-Path $iniPath) {
  try {
    $raw = [System.IO.File]::ReadAllText($iniPath)
    $raw = $raw.Replace([string][char]0xFEFF, '').Replace([string][char]0, '')
    foreach ($line in ($raw -split "`r?`n")) {
      $l = $line.Trim()
      if ($l.Length -eq 0 -or $l[0] -eq '#' -or $l[0] -eq ';' -or $l[0] -eq '[') { continue }
      $i = $l.IndexOf('=')
      if ($i -lt 1) { continue }
      $k = $l.Substring(0, $i).Trim().ToUpper()
      $v = $l.Substring($i + 1).Trim()
      if ($cfg.ContainsKey($k)) { $cfg[$k] = $v }
    }
  } catch { Write-Host '[!] INI read failed - using built-in defaults' }
}

foreach ($k in @('INTERVAL_SEC','ENABLE_DNS','ENABLE_INET','ENABLE_GW','ENABLE_ADAPTER','INET_PORT','TCP_SLOW_MS','DNS_SLOW_MS','TIMEOUT_MS')) {
  $n = 0
  if ([int]::TryParse([string]$cfg[$k], [ref]$n)) { $cfg[$k] = $n }
}

# ---- auto-detect gateway ----
if ([string]::IsNullOrWhiteSpace([string]$cfg['GW_IP'])) {
  $gwAuto = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
             Sort-Object RouteMetric | Select-Object -First 1).NextHop
  if ($gwAuto) { $cfg['GW_IP'] = [string]$gwAuto } else { $cfg['GW_IP'] = '192.168.1.1' }
}

# ---- auto-detect local DNS server ----
$dnsLocal = ''
try {
  $d = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
       Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } |
       Where-Object { $_.InterfaceAlias -notmatch 'Loopback' } |
       Select-Object -First 1
  if ($d) { $dnsLocal = [string]$d.ServerAddresses[0] }
} catch {}
if ([string]::IsNullOrWhiteSpace($dnsLocal)) { $dnsLocal = [string]$cfg['GW_IP'] }

Write-Host '=================================================='
Write-Host ' Net Monitor started'
Write-Host (' Interval        : {0} s' -f $cfg['INTERVAL_SEC'])
Write-Host (' Local DNS       : ' + $dnsLocal)
Write-Host (' External DNS    : ' + $cfg['DNS_EXT'])
Write-Host (' Inet probe      : ' + $cfg['INET_HOST'] + ':' + $cfg['INET_PORT'])
Write-Host (' Gateway         : ' + $cfg['GW_IP'])
Write-Host (' Log folder      : ' + $base)
Write-Host '=================================================='

function Fmt($v) {
  if ($v -is [double] -or $v -is [single] -or $v -is [long]) {
    return $v.ToString('0.0', [System.Globalization.CultureInfo]::InvariantCulture)
  }
  return [string]$v
}

function Test-Tcp {
  param($h, $port, $timeoutMs)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $c = New-Object System.Net.Sockets.TcpClient
  try {
    $ar = $c.BeginConnect([string]$h, [int]$port, $null, $null)
    if ($ar.AsyncWaitHandle.WaitOne($timeoutMs)) {
      try {
        $c.EndConnect($ar)
        $sw.Stop()
        return , @([math]::Round($sw.Elapsed.TotalMilliseconds, 1), 1)
      } catch { return , @(-1, 0) }
    }
    return , @(-1, 0)
  } catch { return , @(-1, 0) }
  finally { try { $c.Close() } catch {} }
}

function Test-Icmp {
  param($h, $timeoutMs)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $p = New-Object System.Net.NetworkInformation.Ping
    $r = $p.Send([string]$h, $timeoutMs)
    $sw.Stop()
    if ($r -and $r.Status -eq 'Success') { return , @([math]::Round($sw.Elapsed.TotalMilliseconds, 1), 1) }
    return , @(-1, 0)
  } catch { return , @(-1, 0) }
}

function Test-DnsUdp {
  param($server, $name, $timeoutMs)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  try {
    $q = New-Object System.Collections.Generic.List[byte]
    $q.Add([byte](Get-Random -Maximum 256)); $q.Add([byte](Get-Random -Maximum 256))
    $q.AddRange([byte[]]@(0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0))
    foreach ($lab in ([string]$name).Split('.')) {
      $b = [System.Text.Encoding]::ASCII.GetBytes($lab)
      $q.Add([byte]$b.Length)
      $q.AddRange($b)
    }
    $q.Add([byte]0)
    $q.AddRange([byte[]]@(0, 1, 0, 1))
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
      $udp.Client.ReceiveTimeout = $timeoutMs
      $udp.Client.SendTimeout = $timeoutMs
      $udp.Connect([string]$server, 53)
      $null = $udp.Send($q.ToArray(), $q.Count)
      $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
      $r = $udp.Receive([ref]$ep)
      $sw.Stop()
      if ($r -and $r.Length -ge 12) { return , @([math]::Round($sw.Elapsed.TotalMilliseconds, 1), 1) }
      return , @(-1, 0)
    } finally { $udp.Close() }
  } catch { return , @(-1, 0) }
}

function Get-LogFile {
  $p = Join-Path $base ('net_log_' + (Get-Date -Format 'yyyyMMdd') + '.csv')
  if (-not (Test-Path $p)) {
    'Time,DnsLocal_ms,DnsLocal_ok,DnsExt_ms,DnsExt_ok,Inet_ms,Inet_ok,Gw_ms,Gw_ok,Adapter,Mark,Note' |
      Out-File -FilePath $p -Encoding UTF8
  }
  return $p
}

while ($true) {
  $note = @()
  $mark = 0
  $markPath = Join-Path $base 'MARK'
  if (Test-Path $markPath) {
    $mark = 1
    Remove-Item $markPath -Force -ErrorAction SilentlyContinue
    $note += 'MARK'
  }

  $dl = @(-1, -1); $dx = @(-1, -1); $inet = @(-1, -1); $gw = @(-1, -1); $adp = -1

  if ($cfg['ENABLE_DNS'] -eq 1) {
    $dl = Test-DnsUdp -server $dnsLocal -name ([string]$cfg['DNS_NAME']) -timeoutMs $cfg['TIMEOUT_MS']
    $dx = Test-DnsUdp -server ([string]$cfg['DNS_EXT']) -name ([string]$cfg['DNS_NAME']) -timeoutMs $cfg['TIMEOUT_MS']
  }
  if ($cfg['ENABLE_INET'] -eq 1) {
    $inet = Test-Tcp -h ([string]$cfg['INET_HOST']) -port ([int]$cfg['INET_PORT']) -timeoutMs $cfg['TIMEOUT_MS']
  }
  if ($cfg['ENABLE_GW'] -eq 1) {
    $gw = Test-Icmp -h ([string]$cfg['GW_IP']) -timeoutMs $cfg['TIMEOUT_MS']
  }
  if ($cfg['ENABLE_ADAPTER'] -eq 1) {
    $adp = 1
    try {
      $bad = @(Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { @('Down','Disabled','Not Present') -contains $_.Status })
      if ($bad.Count -gt 0) {
        $adp = 0
        $note += ('ADP_DOWN:' + (($bad | ForEach-Object { $_.Name + '=' + $_.Status }) -join ','))
      }
    } catch { $adp = -1 }
  }

  if ($cfg['ENABLE_DNS'] -eq 1) {
    if ($dl[1] -eq 0) { $note += 'DNSL_FAIL' } elseif ($dl[0] -ge $cfg['DNS_SLOW_MS']) { $note += 'DNSL_SLOW' }
    if ($dx[1] -eq 0) { $note += 'DNSX_FAIL' } elseif ($dx[0] -ge $cfg['DNS_SLOW_MS']) { $note += 'DNSX_SLOW' }
  }
  if ($cfg['ENABLE_INET'] -eq 1) {
    if ($inet[1] -eq 0) { $note += 'INET_FAIL' } elseif ($inet[0] -ge $cfg['TCP_SLOW_MS']) { $note += 'INET_SLOW' }
  }
  if ($cfg['ENABLE_GW'] -eq 1) {
    if ($gw[1] -eq 0) { $note += 'GW_FAIL' } elseif ($gw[0] -ge 50) { $note += 'GW_SLOW' }
  }

  $status = ('{0}  DNSloc={1}/{2}  DNSext={3}/{4}  Inet={5}/{6}  GW={7}/{8}  Adp={9}  {10}' -f `
    (Get-Date -Format 'HH:mm:ss'), $dl[0], $dl[1], $dx[0], $dx[1], $inet[0], $inet[1], $gw[0], $gw[1], $adp, ($note -join ','))
  Write-Host $status

  $time = Get-Date -Format 'dd.MM.yyyy HH:mm:ss'
  $parts = @($time, (Fmt $dl[0]), [string]$dl[1], (Fmt $dx[0]), [string]$dx[1],
             (Fmt $inet[0]), [string]$inet[1], (Fmt $gw[0]), [string]$gw[1],
             [string]$adp, [string]$mark, ($note -join ';'))
  $line = [string]::Join(',', $parts)
  Add-Content -Path (Get-LogFile) -Value $line -Encoding UTF8

  Start-Sleep -Seconds ([int]$cfg['INTERVAL_SEC'])
}
