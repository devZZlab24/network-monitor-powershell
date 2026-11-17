# ============================================================
#  analyzer.ps1 - structured report over net_log_*.csv
# ============================================================
$ErrorActionPreference = 'SilentlyContinue'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $dir
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$cult = [System.Globalization.CultureInfo]::GetCultureInfo('ru-RU')

# --- thresholds from monitor.ini (tolerant) ---
$DNS_SLOW_MS  = 1500
$TCP_SLOW_MS  = 2000
$PING_SLOW_MS = 200
$iniPath = Join-Path $dir 'monitor.ini'
if (Test-Path $iniPath) {
  foreach ($line in (Get-Content $iniPath -ErrorAction SilentlyContinue)) {
    if ($line -match '^\s*DNS_SLOW_MS\s*=\s*(\d+)')  { $DNS_SLOW_MS  = [int]$Matches[1] }
    if ($line -match '^\s*TCP_SLOW_MS\s*=\s*(\d+)')  { $TCP_SLOW_MS  = [int]$Matches[1] }
    if ($line -match '^\s*PING_SLOW_MS\s*=\s*(\d+)') { $PING_SLOW_MS = [int]$Matches[1] }
  }
}

$out = New-Object System.Collections.Generic.List[string]
function W { param([string]$s = ''); $script:out.Add($s) | Out-Null }

function ParseMs([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return -1.0 }
  $s = $s.Trim()
  if ($s -eq '-1') { return -1.0 }
  $v = 0.0
  if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$v)) { return $v }
  if ([double]::TryParse($s, [System.Globalization.NumberStyles]::Float, $script:cult, [ref]$v)) { return $v }
  return -1.0
}

function ParseTime([string]$s) {
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $d = [datetime]::MinValue
  foreach ($f in @('dd.MM.yyyy HH:mm:ss','dd.MM.yyyy HH:mm','yyyy-MM-dd HH:mm:ss','yyyy-MM-dd HH:mm')) {
    if ([datetime]::TryParseExact($s.Trim(), $f, $script:cult, [System.Globalization.DateTimeStyles]::None, [ref]$d)) { return $d }
  }
  $d2 = [datetime]::MinValue
  if ([datetime]::TryParse($s, $script:cult, [System.Globalization.DateTimeStyles]::None, [ref]$d2)) { return $d2 }
  return $null
}

# --- загрузчик логов ---
$files = @(Get-ChildItem -Path $dir -Filter 'net_log_*.csv' -ErrorAction SilentlyContinue | Sort-Object Name)
if ($files.Count -eq 0) {
  W '=== ЛОГИ НЕ НАЙДЕНЫ ==='
  W 'В папке нет файлов net_log_*.csv. Запустить start_monitor.bat, дать поработать и потом открывать report.bat там будут отчеты с возможными проблемами.'
  $repFile = Join-Path $dir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
  $out | Out-File -FilePath $repFile -Encoding utf8
  Write-Host ($out -join [Environment]::NewLine)
  Write-Host ("Report saved: " + $repFile)
  exit
}

$allRows = @()
foreach ($f in $files) { $allRows += @(Import-Csv -Path $f.FullName -ErrorAction SilentlyContinue) }

$badRows = 0
$data = New-Object System.Collections.Generic.List[object]
foreach ($r in $allRows) {
  $o1 = $r.DnsLocal_ok; $o2 = $r.DnsExt_ok; $o3 = $r.Inet_ok; $o4 = $r.Gw_ok
  $broken = $false
  foreach ($v in @($o1, $o2, $o3, $o4)) { if ($v -ne '0' -and $v -ne '1') { $broken = $true } }
  if ($broken) { $badRows++; continue }
  $t = ParseTime $r.Time
  if ($t -eq $null) { $badRows++; continue }
  $data.Add([pscustomobject]@{
    T      = $t
    DnsL   = (ParseMs $r.DnsLocal_ms); DnsLOk = ($o1 -eq '1')
    DnsE   = (ParseMs $r.DnsExt_ms);   DnsEOk = ($o2 -eq '1')
    Inet   = (ParseMs $r.Inet_ms);     InetOk = ($o3 -eq '1')
    Gw     = (ParseMs $r.Gw_ms);       GwOk   = ($o4 -eq '1')
    Mark   = ($r.Mark -eq '1')
    Note   = [string]$r.Note
  }) | Out-Null
}
$data = @($data | Sort-Object T)

if ($data.Count -eq 0) {
  W '=== ДАННЫХ НЕТ ==='
  W ("Найдено {0} файлов логов, но все {1} строк повреждены (нули -1)." -f $files.Count, $badRows)
  $repFile = Join-Path $dir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
  $out | Out-File -FilePath $repFile -Encoding utf8
  Write-Host ($out -join [Environment]::NewLine)
  exit
}

function MetricStats {
  param($okProp, $msProp, $slowThr)
  $total = $data.Count
  $okRows = @($data | Where-Object { $_.$okProp })
  $ms = @($okRows | ForEach-Object { $_.$msProp } | Where-Object { $_ -ge 0 })
  $slow = @($ms | Where-Object { $_ -gt $slowThr }).Count
  $avg = 0.0; $max = 0.0
  if ($ms.Count -gt 0) {
    $avg = ($ms | Measure-Object -Average).Average
    $max = ($ms | Measure-Object -Maximum).Maximum
  }
  [pscustomobject]@{ Ok = $okRows.Count; Fail = ($total - $okRows.Count); Slow = $slow; Avg = [math]::Round($avg,1); Max = [math]::Round($max,1) }
}

# ============================================================
#  SECTION 1 - overall summary
# ============================================================
W '=== 1. ОБЩАЯ СВОДКА ==='
W ("Период наблюдения : {0} - {1}" -f $data[0].T.ToString('dd.MM.yyyy HH:mm', $cult), $data[$data.Count-1].T.ToString('dd.MM.yyyy HH:mm', $cult))
W ("Обработано строк  : {0}   (повреждённых пропущено: {1})" -f $data.Count, $badRows)
W ("Пороги: DNS медленный > {0} ms, интернет медленный > {1} ms, роутер медленный > {2} ms" -f $DNS_SLOW_MS, $TCP_SLOW_MS, $PING_SLOW_MS)
W ''
$mDnsL = MetricStats 'DnsLOk' 'DnsL' $DNS_SLOW_MS
$mDnsE = MetricStats 'DnsEOk' 'DnsE' $DNS_SLOW_MS
$mInet = MetricStats 'InetOk' 'Inet' $TCP_SLOW_MS
$mGw   = MetricStats 'GwOk'   'Gw'   $PING_SLOW_MS
$tbl1 = @(
  [pscustomobject]@{ 'Проверка' = 'DNS локальный (ваш)' ; 'Успешно' = $mDnsL.Ok; 'Сбоев' = $mDnsL.Fail; 'Медленно' = $mDnsL.Slow; 'Среднее, ms' = $mDnsL.Avg; 'Макс, ms' = $mDnsL.Max }
  [pscustomobject]@{ 'Проверка' = 'DNS внешний 1.1.1.1'  ; 'Успешно' = $mDnsE.Ok; 'Сбоев' = $mDnsE.Fail; 'Медленно' = $mDnsE.Slow; 'Среднее, ms' = $mDnsE.Avg; 'Макс, ms' = $mDnsE.Max }
  [pscustomobject]@{ 'Проверка' = 'Интернет (TCP 443)'   ; 'Успешно' = $mInet.Ok; 'Сбоев' = $mInet.Fail; 'Медленно' = $mInet.Slow; 'Среднее, ms' = $mInet.Avg; 'Макс, ms' = $mInet.Max }
  [pscustomobject]@{ 'Проверка' = 'Роутер (ping)'        ; 'Успешно' = $mGw.Ok;   'Сбоев' = $mGw.Fail;   'Медленно' = $mGw.Slow;   'Среднее, ms' = $mGw.Avg;   'Макс, ms' = $mGw.Max }
)
W '--- Качество каждой проверки за весь период ---'
W (($tbl1 | Format-Table -AutoSize | Out-String -Width 200).TrimEnd())
W ''

# ============================================================
#  SECTION 2 - per hour
# ============================================================
W '=== 2. РАЗБИВКА ПО ЧАСАМ ==='
W 'Час       | Строк | INET fail | GW fail | DNS fail | Медленных замеров'
W '----------|-------|-----------|---------|----------|------------------'
$hours = $data | Group-Object { $_.T.ToString('dd.MM HH', $cult) } | Sort-Object Name
foreach ($g in $hours) {
  $g2 = @($g.Group)
  $inetF = @($g2 | Where-Object { -not $_.InetOk }).Count
  $gwF   = @($g2 | Where-Object { -not $_.GwOk }).Count
  $dnsF  = @($g2 | Where-Object { (-not $_.DnsLOk) -or (-not $_.DnsEOk) }).Count
  $slowC = @($g2 | Where-Object { ($_.InetOk -and $_.Inet -gt $TCP_SLOW_MS) -or ($_.GwOk -and $_.Gw -gt $PING_SLOW_MS) -or ($_.DnsLOk -and $_.DnsL -gt $DNS_SLOW_MS) -or ($_.DnsEOk -and $_.DnsE -gt $DNS_SLOW_MS) }).Count
  W ("{0} | {1,5} | {2,9} | {3,7} | {4,8} | {5,9}" -f $g.Name, $g2.Count, $inetF, $gwF, $dnsF, $slowC)
}
W ''

# ============================================================
#  SECTION 3 - incidents
# ============================================================
W '=== 3. ИНЦИДЕНТЫ (каждый сбой отдельно) ==='
$bad = @()
foreach ($d in $data) {
  $fl = @()
  if (-not $d.InetOk)                        { $fl += 'INET_FAIL' }
  if (-not $d.GwOk)                          { $fl += 'GW_FAIL' }
  if (-not $d.DnsLOk)                        { $fl += 'DNSL_FAIL' }
  if (-not $d.DnsEOk)                        { $fl += 'DNSE_FAIL' }
  if ($d.InetOk -and $d.Inet -gt $TCP_SLOW_MS)  { $fl += 'INET_SLOW' }
  if ($d.GwOk   -and $d.Gw   -gt $PING_SLOW_MS) { $fl += 'GW_SLOW' }
  if (($d.DnsLOk -and $d.DnsL -gt $DNS_SLOW_MS) -or ($d.DnsEOk -and $d.DnsE -gt $DNS_SLOW_MS)) { $fl += 'DNS_SLOW' }
  if ($fl.Count -gt 0) { $bad += [pscustomobject]@{ T = $d.T; Fl = @($fl | Select-Object -Unique) } }
}
if ($bad.Count -eq 0) {
  W 'Ни одного сбоя за весь период. Сеть работала стабильно.'
} else {
  $incidents = New-Object System.Collections.Generic.List[object]
  $cur = $null
  foreach ($b in $bad) {
    if ($cur -ne $null -and (($b.T - $cur.End).TotalSeconds -le 120)) {
      $cur.End = $b.T; $cur.Count++
      foreach ($flg in $b.Fl) { if ($cur.Flags -notcontains $flg) { $cur.Flags += $flg } }
    } else {
      if ($cur -ne $null) { $incidents.Add($cur) | Out-Null }
      $cur = [pscustomobject]@{ Start = $b.T; End = $b.T; Count = 1; Flags = @($b.Fl) }
    }
  }
  if ($cur -ne $null) { $incidents.Add($cur) | Out-Null }

  W ("Найдено инцидентов: {0}" -f $incidents.Count)
  W ''
  W 'Начало              | Длился  | Замеров | Что падало                          | Подозреваемый'
  W '--------------------|---------|---------|-------------------------------------|----------------------------------------'
  foreach ($i in $incidents) {
    $dur = ($i.End - $i.Start).TotalSeconds
    if ($dur -ge 60) { $durStr = ('{0:N0} мин {1:D2} сек' -f [int][math]::Floor($dur/60), [int]($dur % 60)) }
    else             { $durStr = ('{0:N0} сек' -f $dur) }
    $culprit = '?'
    if ($i.Flags -contains 'GW_FAIL' -or $i.Flags -contains 'GW_SLOW') { $culprit = 'ЛОКАЛЬНАЯ СЕТЬ: Wi-Fi, кабель, роутер' }
    elseif ($i.Flags -contains 'INET_FAIL' -or $i.Flags -contains 'INET_SLOW') { $culprit = 'КАНАЛ ДО ИНТЕРНЕТА: провайдер / WAN' }
    elseif ($i.Flags -contains 'DNSL_FAIL') { $culprit = 'DNS (ваш / на роутере)' }
    elseif ($i.Flags -contains 'DNSE_FAIL') { $culprit = 'DNS (внешний резолвер)' }
    elseif ($i.Flags -contains 'DNS_SLOW')  { $culprit = 'DNS медленный' }
    $fstr = ($i.Flags -join ', ')
    if ($fstr.Length -gt 35) { $fstr = $fstr.Substring(0, 35) }
    W ("{0} | {1,7} | {2,7} | {3,-35} | {4}" -f $i.Start.ToString('dd.MM HH:mm:ss', $cult), $durStr, $i.Count, $fstr, $culprit)
  }
}
W ''

# ============================================================
#  SECTION 4 - manual MARKs and Windows events
# ============================================================
$marks = @($data | Where-Object { $_.Mark })
W '=== 4. РУЧНЫЕ МЕТКИ (файл MARK) ==='
if ($marks.Count -gt 0) {
  foreach ($m in $marks) { W ("  {0}  <-- Увидел сбой" -f $m.T.ToString('dd.MM HH:mm:ss', $cult)) }
  W ''
  W 'Здесь надо сравнить метки с инцидентами из раздела 3: если рядом с меткой есть инцидент - он реальный.'
  W 'Если меток нет, а инциденты есть - смотреть самые длинные инциденты.'
} else {
  W 'Если меток не ставил. Смотри раздел 3 - там все найденные сбои.'
}
W ''

$evts = @($data | Where-Object { $_.Note.Trim() -ne '' } | Select-Object -ExpandProperty Note | Select-Object -Unique)
W '=== 5. СОБЫТИЯ WINDOWS / ПРОЧИЕ ЗАМЕТКИ ==='
if ($evts.Count -gt 0) {
  foreach ($e in $evts) { W ("  {0}" -f $e) }
} else {
  W 'Windows не сообщала о сетевых событиях за этот период.'
}
W ''

# ============================================================
#  SECTION 6 - diagnoses
# ============================================================
W '=== 6. ДИАГНОЗЫ (что было найдено и что делать) ==='
$diagPath = Join-Path $dir 'diagnoses.txt'
$diags = @{}
if (Test-Path $diagPath) {
  foreach ($line in (Get-Content $diagPath -Encoding UTF8 -ErrorAction SilentlyContinue)) {
    $p = $line -split '\|'
    if ($p.Count -ge 4) { $diags[$p[0].Trim()] = @{ Title = $p[1].Trim(); Meaning = $p[2].Trim(); Action = $p[3].Trim() } }
  }
}
$flagOrder = @('INET_FAIL','INET_SLOW','GW_FAIL','GW_SLOW','DNSL_FAIL','DNSE_FAIL','DNS_SLOW')
$found = @{}
foreach ($b in $bad) { foreach ($f in $b.Fl) { if (-not $found.ContainsKey($f)) { $found[$f] = 0 }; $found[$f]++ } }
$anyDiag = $false
foreach ($f in $flagOrder) {
  if (-not $found.ContainsKey($f)) { continue }
  $anyDiag = $true
  $cnt = $found[$f]
  $title = $f; $meaning = ''; $action = ''
  if ($diags.ContainsKey($f)) { $title = $diags[$f].Title; $meaning = $diags[$f].Meaning; $action = $diags[$f].Action }
  W ''
  W ("[{0}] - {1} (случаев: {2})" -f $f, $title, $cnt)
  if ($meaning) { W ("    Что это:   {0}" -f $meaning) }
  if ($action)  { W ("    Что делать:{0}{1}" -f [Environment]::NewLine, $action) }
}
if (-not $anyDiag) { W 'Проблем не обнаружено - диагнозы не требуются.' }
W ''

# ============================================================
#  SECTION 7 - final verdict
# ============================================================
W '=== 7. ИТОГОВЫЙ ВЕРДИКТ ==='
$pctGwF   = [math]::Round(100.0 * $mGw.Fail / $data.Count, 2)
$pctInetF = [math]::Round(100.0 * $mInet.Fail / $data.Count, 2)
$pctDnsF  = [math]::Round(100.0 * (($mDnsL.Fail + $mDnsE.Fail) / 2.0) / $data.Count, 2)
if ($pctGwF -gt 1.0) {
  W ("Связь с роутером рвалась в {0}% замеров." -f $pctGwF)
  W 'ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ: локальная сеть - Wi-Fi сигнал, кабель до роутера или сам роутер.'
  W 'Начните с: передвинуться ближе к роутеру / перезагрузить роутер / проверить кабель.'
} elseif ($pctInetF -gt 1.0) {
  W ("Интернет пропадал в {0}% замеров, при этом роутер отвечал нормально." -f $pctInetF)
  W 'ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ: провайдер или WAN-канал. С этими цифрами можно идти к провайдеру.'
} elseif ($pctDnsF -gt 1.0) {
  W ("DNS сбоил/тормозил в {0}% замеров, сам канал был жив." -f $pctDnsF)
  W 'ГЛАВНЫЙ ПОДОЗРЕВАЕМЫЙ: DNS. Это и есть ваши зависания на 10-40 секунд.'
  W 'Что делать: пропишите в настройках сетевого адаптера DNS 1.1.1.1 и 8.8.8.8 вместо автоматического.'
} elseif ($mInet.Slow + $mDnsL.Slow + $mDnsE.Slow -gt 0) {
  W 'Полных пропаданий нет, но были периоды деградации (медленные ответы).'
  W 'Смотрите раздел 3: если в инцидентах растёт роутер - Wi-Fi, если только интернет - канал провайдера.'
} else {
  W 'За период наблюдения сеть работала стабильно. Если зависания были - поставьте метку MARK в момент сбоя и повторите замер.'
}

# --- save and print ---
$repFile = Join-Path $dir ('report_' + (Get-Date -Format 'yyyyMMdd_HHmmss') + '.txt')
$out | Out-File -FilePath $repFile -Encoding utf8
foreach ($line in $out) {
  if ($line -like '===*')  { Write-Host $line -ForegroundColor Cyan }
  elseif ($line -like '---*') { Write-Host $line -ForegroundColor Yellow }
  elseif ($line -like '*ЛОКАЛЬНАЯ СЕТЬ*') { Write-Host $line -ForegroundColor Red }
  elseif ($line -like '*провайдер*') { Write-Host $line -ForegroundColor Magenta }
  else { Write-Host $line }
}
Write-Host ''
Write-Host ('Отчёт сохранён в файл: ' + $repFile) -ForegroundColor Green
