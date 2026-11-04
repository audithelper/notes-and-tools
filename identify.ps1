$f = "C:\loot\unfichier"
$bytes = [System.IO.File]::ReadAllBytes($f)
foreach ($cp in 1047,1147,500,37,297,1140) {
    try {
        $enc = [System.Text.Encoding]::GetEncoding($cp)
        $txt = $enc.GetString($bytes)
        Write-Host "`n===== CP $cp =====" -ForegroundColor Cyan
        Write-Host ($txt -split "`n" | Select-Object -First 5)
    } catch { Write-Host "CP $cp indisponible" }
}
