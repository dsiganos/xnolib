#!/usr/bin/env python3

import requests
import json
import argparse
import peercrawler
import pynanocoin
import acctools
import constants

#def parse_args():
#    parser = argparse.ArgumentParser()
#    parser.add_argument('-p', '--peerdetails', action='store_true', default=False,
#                        help='Request peer details')
#    return parser.parse_args()
#
#args = parse_args()


RPC_URL = 'http://[::1]:7076'
#RPC_URL = 'https://mynano.ninja/api/node'


def weight_to_percentage(weight):
    return weight * 100 / constants.max_nano_supply


class Representative:
    def __init__(self):
        self.account = None
        self.endpoint = None
        self.weight = None
        self.node_id = None
        self.protover = None
        self.voting = None

    def __str__(self):
        friendly_str = acctools.to_friendly_name(self.account)
        if friendly_str != '':
            friendly_str = ' (' + friendly_str + ')'
        s = ''
        s += 'Account:  %s%s\n'     % (self.account, friendly_str)
        s += '  FriendlyName: %s\n' % acctools.to_friendly_name(self.account)
        s += '  Endpoint: %s\n'     % self.endpoint
        s += '  Node ID:  %s\n'     % self.node_id
        s += '  Weight: %s (%s)\n'  % (self.weight, weight_to_percentage(int(self.weight)))
        s += '  ProtoVer: %s, '     % self.protover
        s += '  Voting: %s'         % self.voting
        return s
        

def post(session, params, timeout=5):
    resp = session.post(RPC_URL, json=params, timeout=5)
    return resp.json()


def get_confirmation_quorum(session):
    params = {
      'action': 'confirmation_quorum',
      'peer_details': 'true',
    }
    result = post(session, params)
    return result


def get_peers(session):
    params = {
      'action': 'peers',
      'peer_details': 'true',
    }
    result = post(session, params)
    return result


def get_representatives(session):
    params = {
      'action': 'representatives',
    }
    result = post(session, params)
    return result


def get_representatives_details():
    session = requests.Session()

    quorum_reply = get_confirmation_quorum(session)
    peers_reply = get_peers(session)
    #reps_reply = get_representatives(session)

    reps = set()

    # issue rpc confirmation quorum to get the list of reps
    for p in quorum_reply['peers']:
        rep = Representative()
        rep.account  = p['account']
        rep.endpoint = p['ip']
        rep.weight   = p['weight']
        reps.add(rep)

    # merge in info obtain by rpc call peers (node IDs and protocol version)
    peers = peers_reply['peers']
    for peer_addr in peers:
        for rep in reps:
            if peer_addr == rep.endpoint:
                rep.node_id = peers[peer_addr]['node_id']
                rep.protover = peers[peer_addr]['protocol_version']

    # merge in voting capabilities from peercrawler
    _, peers = peercrawler.get_peers_from_service(pynanocoin.livectx)
    for peer in peers:
        for rep in reps:
            if peer.peer_id:
                if acctools.to_account_addr(peer.peer_id, prefix='node_') == rep.node_id:
                    rep.voting = peer.is_voting

    return reps


def main():
    for rep in get_representatives_details():
        pass
        print(rep)


if __name__ == "__main__":
    main()
