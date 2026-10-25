# q1-009: CVE-publication -> CISA KEV lag for middle-tier servers (KEV dateAdded >= 2025-01-01).
# Usage: python3 -I kevmid.py kev.json out.json
#   kev.json = https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
# CVE publish date and finder credits come from CVEProject/cvelistV5 (main branch, raw GitHub).
# KEV dateAdded is an UPPER bound on first exploitation; CVE datePublished can lag the GHSA/vendor advisory.
import json, sys, urllib.request, datetime, statistics

kev = json.load(open(sys.argv[1]))['vulnerabilities']
MID = {
    'proxy/ADC/gateway': [('Citrix', 'NetScaler'), ('F5', 'BIG-IP'), ('Progress', 'LoadMaster'),
                          ('Array Networks', 'ArrayOS'), ('Fortinet', 'FortiProxy'), ('Fortinet', 'FortiWeb'),
                          ('Ivanti', 'Connect Secure'), ('Check Point', 'Security Gateway'),
                          ('Oracle', 'HTTP Server'), ('BerriAI', 'LiteLLM'), ('Aviatrix', 'Controllers')],
    'web/app server': [('Apache', 'HTTP Server'), ('Apache', 'Tomcat'), ('Oracle', 'WebLogic'),
                       ('Erlang', 'Erlang/OTP'), ('Oracle', 'Fusion Middleware')],
    'app framework': [('Meta', 'React Server Components'), ('Kludex', 'Starlette'), ('Laravel', 'Livewire'),
                      ('Rails', 'Ruby on Rails'), ('Yiiframework', 'Yii'), ('Apache', 'Struts'),
                      ('Ajax.NET', 'Ajax.NET')],
}
OSS_VENDORS = {'Apache', 'Erlang', 'Meta', 'Kludex', 'Laravel', 'BerriAI', 'Yiiframework', 'Rails',
               'Ajax.NET Professional'}


def cat(v):
    for c, pairs in MID.items():
        for vp, p in pairs:
            if vp.lower() in v['vendorProject'].lower() and p.lower() in v['product'].lower():
                return c


rows = []
for v in kev:
    if v['dateAdded'] < '2025-01-01':
        continue
    c = cat(v)
    if not c:
        continue
    cve = v['cveID']
    y, n = cve.split('-')[1], cve.split('-')[2]
    url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{n[:-3]}xxx/{cve}.json"
    pub, credits = '?', []
    try:
        j = json.load(urllib.request.urlopen(url, timeout=30))
        pub = j['cveMetadata'].get('datePublished', '')[:10]
        for cont in [j['containers'].get('cna', {})] + j['containers'].get('adp', []):
            credits += [x.get('value', '')[:80] for x in cont.get('credits', [])]
    except Exception:
        pass
    lag = (datetime.date.fromisoformat(v['dateAdded']) - datetime.date.fromisoformat(pub)).days if pub != '?' else None
    rows.append(dict(cve=cve, cat=c, vendor=v['vendorProject'].strip(), product=v['product'].strip(),
                     cve_published=pub, kev_added=v['dateAdded'], lag_days=lag,
                     ransomware=v.get('knownRansomwareCampaignUse'), name=v['vulnerabilityName'],
                     credits=credits))
rows.sort(key=lambda r: r['kev_added'])
json.dump(rows, open(sys.argv[2], 'w'), indent=1)


def stats(name, s):
    l = [r['lag_days'] for r in s if r['lag_days'] is not None]
    print(name, 'n', len(l), 'median', statistics.median(l), 'day0', sum(x <= 0 for x in l),
          '<=2d', sum(x <= 2 for x in l), '<=7d', sum(x <= 7 for x in l), '<=30d', sum(x <= 30 for x in l))


stats('all KEV-added 2025+', rows)
new = [r for r in rows if r['cve_published'] >= '2025-01-01']
stats('CVE published 2025+', new)
stats('  OSS subset', [r for r in new if r['vendor'] in OSS_VENDORS])
stats('  appliance/commercial subset', [r for r in new if r['vendor'] not in OSS_VENDORS])
