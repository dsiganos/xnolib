import requests
import json

from peercrawler import get_peers_from_service
from pynanocoin import livectx
from peer import Peer

URL = 'http://hetzner1.siganos.xyz:5001/peercrawler/json'

session = requests.Session()
resp = session.get(URL, timeout=5)
json_resp = resp.json()

# peers = get_peers_from_service(livectx, "::1")
# print(peers)

# print(json.dumps(json_resp, indent=4))
# print(resp)
# print(json.dumps(json_resp[0], indent=4))
# tel = telemetry_ack.from_json(json_resp[0]['telemetry'])
# print(tel.hdr.ext)
peers = [ Peer.from_json(r) for r in json_resp ]
for r in json_resp:
    # try:
    peer = Peer.from_json(r)
    # except Exception:
    #     print(r)

for p in peers:
    print(p)
