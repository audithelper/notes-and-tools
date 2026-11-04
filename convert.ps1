$src = "C:\loot"
$dst = "C:\loot_txt"
$ebc = [System.Text.Encoding]::GetEncoding(1147)   # ← mets ta page de code
$utf = New-Object System.Text.UTF8Encoding($false) # UTF-8 sans BOM
New-Item -ItemType Directory -Force $dst | Out-Null

Get-ChildItem $src -Recurse -File | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $text  = $ebc.GetString($bytes)
    [System.IO.File]::WriteAllText((Join-Path $dst $_.Name), $text, $utf)
}
Write-Host "Converti dans $dst"
