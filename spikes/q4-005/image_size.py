#!/usr/bin/env python3
"""Exact uncompressed size of a Docker Hub image (amd64) by streaming and gunzipping its layers; nothing is stored.
Usage: python3 -I image_size.py <repo e.g. library/mariadb> <tag>"""
import json, sys, urllib.request, zlib
repo, tag = sys.argv[1], sys.argv[2]
tok = json.load(urllib.request.urlopen(f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"))["token"]
def get(url, acc):
    r = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok, "Accept": acc})
    return urllib.request.urlopen(r)
idx = json.load(get(f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}", "application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json"))
dg = [m for m in idx["manifests"] if m.get("platform", {}).get("architecture") == "amd64"][0]["digest"]
man = json.load(get(f"https://registry-1.docker.io/v2/{repo}/manifests/{dg}", "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"))
tc = tu = 0
for l in man["layers"]:
    r = get(f"https://registry-1.docker.io/v2/{repo}/blobs/{l['digest']}", "*/*")
    d = zlib.decompressobj(31); n = 0
    while True:
        b = r.read(1 << 20)
        if not b: break
        n += len(d.decompress(b))
    n += len(d.flush()); tc += l["size"]; tu += n
print(repo, tag, dg, "compressed_MB", round(tc/1e6,1), "uncompressed_MB", round(tu/1e6,1))
