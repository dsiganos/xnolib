#!/usr/bin/env python3

import copy
import requests
import json
import argparse

import peercrawler
import pynanocoin
import acctools
import constants

RPC_URL = 'http://[::1]:7076'
#RPC_URL = 'https://mynano.ninja/api/node'


class Representative:
    def __init__(self):
        self.account = None
        self.endpoint = None
        self.weight = None
        self.node_id = None
        self.protover = None
        self.voting = None

    def set_weight(self, weight: int) -> None:
        assert isinstance(weight, int)
        self.weight      = weight
        self.weight_perc = weight_to_percentage(weight)

    def __str__(self):
        friendly_str = acctools.to_friendly_name(self.account)
        if friendly_str != '':
            friendly_str = ' (' + friendly_str + ')'
        s = ''
        s += 'Account:  %s%s\n'     % (self.account, friendly_str)
        s += '  FriendlyName: %s\n' % acctools.to_friendly_name(self.account)
        s += '  Endpoint: %s\n'     % self.endpoint
        s += '  Node ID:  %s\n'     % self.node_id
        s += '  Weight: %s (%s)\n'  % (self.weight, self.weight_perc)
        s += '  ProtoVer: %s, '     % self.protover
        s += '  Voting: %s'         % self.voting
        return s
        

class Quorum:
    def __init__(self):
        self.online_weight                = None
        self.delta                        = None
        self.online_weight_quorum_percent = None
        self.online_weight_minimum        = None
        self.online_stake_total           = None
        self.peers_stake_total            = None
        self.trended_stake_total          = None

    def set_delta(self, delta: int) -> None:
        self.delta = delta
        self.online_weight = int(delta * (100 / self.online_weight_quorum_percent))

    def __str__(self):
        s = 'Quorum:\n'
        s += 'Online Weight                : {:,}\n'.format(self.online_weight)
        s += 'Quorum Delta                 : {:,}\n'.format(self.delta)
        s += 'Online Weight Quorum Minimum : {:,}\n'.format(self.online_weight_quorum_percent)
        s += 'Online Weight Minimum        : {:,}\n'.format(self.online_weight_minimum)
        s += 'Online Stake Total           : {:,}\n'.format(self.online_stake_total)
        s += 'Peers Stake Total            : {:,}\n'.format(self.peers_stake_total)
        s += 'Trended Stake Total          : {:,}'  .format(self.trended_stake_total)
        return s


def weight_to_percentage(weight: int) -> float:
    return weight * 100 / constants.max_nano_supply


# return the rep object if endpoint is a rep and has at least 'weight' raw weight
# return None otherwise
def endpoint_to_rep(reps: list[Representative], endpoint: str, weight: int) -> Representative:
    if isinstance(reps, list):
        for rep in reps:
            if endpoint == rep.endpoint:
                if rep.weight >= weight:
                    return rep
    elif isinstance(reps, dict):
        for acc, rep in reps.items():
            if endpoint == rep.endpoint:
                if rep.weight >= weight:
                    return rep
    else:
        assert 0


def get_reps_with_weights() -> list[Representative]:
    reps = []
    for acc, rep in get_representatives().items():
        #if isinstance(rep, str):
        #    print('rep is string: %s' % rep)
        #    continue
        #print(rep)
        if rep.weight > 0:
            reps.append(rep)
    return reps


def post(session, params, timeout=5) -> str:
    resp = session.post(RPC_URL, json=params, timeout=5)
    return resp.json()


def rpc_confirmation_quorum(session: requests.Session) -> str:
    params = {
      'action': 'confirmation_quorum',
      'peer_details': 'true',
    }
    result = post(session, params)
    return result


def rpc_peers(session: requests.Session) -> str:
    params = {
      'action': 'peers',
      'peer_details': 'true',
    }
    result = post(session, params)
    return result


def rpc_representatives(session: requests.Session) -> str:
    params = {
      'action': 'representatives',
    }
    result = post(session, params)
    return result


def get_representatives() -> list[Representative]:
    session = requests.Session()

    quorum_reply = rpc_confirmation_quorum(session)
    quorum = Quorum()
    quorum.online_weight_quorum_percent = int(quorum_reply['online_weight_quorum_percent'])
    quorum.online_weight_minimum        = int(quorum_reply['online_weight_minimum'])
    quorum.online_stake_total           = int(quorum_reply['online_stake_total'])
    quorum.peers_stake_total            = int(quorum_reply['peers_stake_total'])
    quorum.trended_stake_total          = int(quorum_reply['trended_stake_total'])
    quorum.set_delta(int(quorum_reply['quorum_delta']))
    print(quorum)

    peers_reply = rpc_peers(session)
    reps_reply = rpc_representatives(session)
    static_reps = { k:v for k,v in reps_reply['representatives'].items() if int(v) > 0 }

    reps = {}

    # add the static representatives first
    for acc, weight in static_reps.items():
        rep = Representative()
        rep.account = acc
        rep.set_weight(int(weight))
        assert acc not in reps.keys()
        reps[acc] = rep

    # get representatives involved in peers_stake_total
    # this call also provides ip addresses for some representatives
    for p in quorum_reply['peers']:
        acc = p['account']
        weight = int(p['weight'])
        if acc in reps.keys():
            rep = reps[acc]
            rep.endpoint = p['ip']
            if weight != rep.weight:
                print('Weight Diff (%s): %s(%s%%) - %s(%s%%) = %s(%s%%)' % (acc,
                    weight, weight_to_percentage(weight),
                    rep.weight, weight_to_percentage(rep.weight),
                    weight - rep.weight, weight_to_percentage(weight - rep.weight)))
                assert rep.weight_perc == weight_to_percentage(rep.weight)

        else:
            rep = Representative()
            rep.account = acc
            rep.endpoint = p['ip']
            rep.set_weight(weight)
            reps[acc] = rep

    # merge in node IDs and protocol version
    peers = peers_reply['peers']
    for endpoint in peers.keys():
        for acc, rep in reps.items():
            if endpoint == rep.endpoint:
                rep.node_id = peers[endpoint]['node_id']
                rep.protover = peers[endpoint]['protocol_version']

    # merge in voting capabilities from peercrawler
    peers = peercrawler.get_peers_from_service(pynanocoin.livectx)
    for peer in peers:
        if peer.peer_id:
            for acc, rep in reps.items():
                if rep.node_id == acctools.to_account_addr(peer.peer_id, prefix='node_'):
                    rep.voting = peer.is_voting

    return reps


def parse_args():
    parser = argparse.ArgumentParser()

    group = parser.add_mutually_exclusive_group()
    group.add_argument('-b', '--beta', action='store_true', default=False,
                       help='use beta network')
    group.add_argument('-t', '--test', action='store_true', default=False,
                       help='use test network')

    group.add_argument('-z', '--zero', action='store_true', default=False,
                       help='show reps with zero weight')

    group.add_argument('-i', '--noip', action='store_true', default=False,
                       help='show reps without an ip address')

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    reps = get_representatives()
    reps_list = sorted(reps.values(), reverse=False, key = lambda rep: rep.weight)

    count = 0
    total_percentage = 0
    for rep in reps_list:
        if args.noip and rep.endpoint:
            continue
        count += 1
        total_percentage += rep.weight_perc
        print(rep)

    print('count = %s' % count)
    print('total percentage = %s' % total_percentage)


if __name__ == "__main__":
    main()
