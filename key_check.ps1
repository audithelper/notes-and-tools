# ===== 1. Your modulus from the mainframe (paste the hex; colons/spaces OK) =====
$myMod = 'PASTE-OPENSSL-MODULUS-HEX-HERE'

# Normalize: strip colons/whitespace, lowercase, remove leading zero BYTES only
$myMod = ($myMod -replace '[:\s]', '').ToLower()
while ($myMod.StartsWith('00') -and $myMod.Length -gt 2) { $myMod = $myMod.Substring(2) }

# ===== 2. Gateway JWKS (public, unauthenticated endpoint) =====
$gwHost = 'your.gateway.host'
$gwPort = 7554    # components.gateway.port from zowe.yaml
$url = "https://${gwHost}:${gwPort}/gateway/api/v1/auth/keys/public/all"

# PS 5.1: allow TLS1.2 + ignore the Zowe self-signed/internal CA cert
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$jwks = Invoke-RestMethod -Uri $url

# ===== 3. Compare =====
function B64uToHex($s) {
   $s = $s.Replace('-','+').Replace('_','/')
   switch ($s.Length % 4) { 2 {$s+='=='} 3 {$s+='='} }
   [byte[]]$b = [Convert]::FromBase64String($s)
   (($b | ForEach-Object { $_.ToString('x2') }) -join '')
}

foreach ($k in $jwks.keys) {
   $n = B64uToHex $k.n
   while ($n.StartsWith('00') -and $n.Length -gt 2) { $n = $n.Substring(2) }
   if ($n -eq $myMod) {
	   Write-Host "MATCH  -> kid=$($k.kid) alg=$($k.alg) use=$($k.use)  <<== YOUR KEY IS THE JWT SIGNING KEY" -ForegroundColor Red
   } else {
	   Write-Host "no     -> kid=$($k.kid) alg=$($k.alg)"
   }
}
