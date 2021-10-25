import json

from pynanocoin import *
import telemetry_req

class NanoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, bytes):
            return hexlify(obj)
        if isinstance(obj, ip_addr):
            return str(obj)
        if isinstance(obj, message_header):
            return obj.__dict__
        if isinstance(obj, network_id):
            return obj.id
        if isinstance(obj, message_type):
            return obj.type
        if isinstance(obj, telemetry_req.telemetry_ack):
            return obj.__dict__
        if isinstance(obj, Peer):
            return obj.__dict__
        return json.JSONEncoder.default(self, obj)


def print_peers(peers):
    assert isinstance(peers, list)
    print(json.dumps(peers, cls=NanoJSONEncoder, indent=4))

