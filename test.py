#!/usr/bin/env python3
import base64, getpass, json, re, ssl, sys
import urllib.request, urllib.parse, urllib.error, http.cookiejar

HOST = sys.argv[1]                       # ex: https://zosmf.client.local
USER = sys.argv[2]
PWD  = getpass.getpass("Mot de passe : ")
KW = re.compile(r"PASS|PWD|PW=|SIGNON|USING|PHRASE\(|-u |PASSWORD\(|SPECIAL|KEYRING|TOKEN", re.I)

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

q = urllib.parse.quote  # noms de jobs avec $, #, @
jobs = json.loads(call("/zosmf/restjobs/jobs",
                       params={"owner": "*", "prefix": "*", "max-jobs": 5000}))
print(f"[+] {len(jobs)} jobs visibles", file=sys.stderr)

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
