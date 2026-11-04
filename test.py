import requests, re, urllib3; urllib3.disable_warnings()
B = "https://HOTE/zosmf/restjobs/jobs"
s = requests.Session(); s.auth = ("USER", "PASS"); s.verify = False
s.headers["X-CSRF-ZOSMF-HEADER"] = "x"
KW = re.compile(r"PASS|PWD|PW=|SIGNON|USING|PHRASE\(|-u |PASSWORD\(|SPECIAL|KEYRING|TOKEN", re.I)

jobs = s.get(B, params={"owner": "*", "prefix": "*", "max-jobs": 5000}).json()
for j in jobs:
    base = f"{B}/{j['jobname']}/{j['jobid']}"
    for f in s.get(f"{base}/files").json():
        txt = s.get(f"{base}/files/{f['id']}/records").text
        for l in txt.splitlines():
            if KW.search(l):
                print(f"{j['jobname']}/{j['jobid']}/{f['ddname']}: {l.strip()}")
