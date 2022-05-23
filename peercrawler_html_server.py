#!/bin/env python3
from datetime import datetime, timedelta

from flask import Flask,jsonify,request,render_template,redirect
import threading

import peercrawler
import pynanocoin
import common
from acctools import to_account_addr
from peercrawler_html_server_utils import *


app = Flask(__name__, static_url_path='/peercrawler')

ctx = pynanocoin.livectx
peerman = peercrawler.peer_manager(ctx, verbosity=1)


# read from a file a list of dicts with info about prs
nodes = try_load_peers_details("peers-details.json")


def bg_thread_func():
    global peerman
    # look for peers forever
    peerman.crawl(forever=True, delay=60)


@app.route("/peercrawler")
def main_website():
    global app, peerman

    peers_copy = list(peerman.get_peers_copy())

    peer_list = []
    for peer in peers_copy:
        telemetry = peer.telemetry
        hdr = {}
        if telemetry != None:
            if telemetry.hdr == None:
                hdr.ext = 0
                hdr.net_id = 0
                hdr.ver_max = 0
                hdr.ver_using = 0
                hdr.ver_min = 0
                hdr.msg_type = 0
            else:
                hdr = telemetry.hdr

            node_id = to_account_addr(telemetry.node_id, "node_")
            node_details = get_node_details_from_id(node_id, nodes)

            peer_list.append([peer.ip,
                              peer.port,
                              common.hexlify(peer.peer_id),
                              peer.is_voting,
                              hdr.ext,
                              hdr.net_id,
                              hdr.ver_max,
                              hdr.ver_using,
                              hdr.ver_min,
                              hdr.msg_type,
                              telemetry.sig_verified,
                              common.hexlify(telemetry.sig),
                              node_id,
                              telemetry.block_count,
                              telemetry.cemented_count,
                              telemetry.unchecked_count,
                              telemetry.account_count,
                              telemetry.bandwidth_cap,
                              telemetry.peer_count,
                              telemetry.protocol_ver,
                              str(timedelta(seconds=telemetry.uptime)),
                              common.hexlify(telemetry.genesis_hash),
                              telemetry.major_ver,
                              telemetry.minor_ver,
                              telemetry.patch_ver,
                              telemetry.pre_release_ver,
                              telemetry.maker_ver,
                              datetime.utcfromtimestamp(telemetry.timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                              telemetry.active_difficulty,
                              peer.aux,
                              peer.score])
        else:
            peer_list.append([peer.ip,
                              peer.port,
                              common.hexlify(peer.peer_id),
                              peer.is_voting,
                              "0", "0", "0", "0", "0", "0", "0", "0",
                              "0", "0", "0", "0", "0", "0", "0", "0",
                              "0", "0", "0", "0", "0", "0", "0", "0",
                              "0", "0",
                              peer.aux, peer.score])

    return render_template('index.html', name=peer_list)


def main():
    # start the peer crawler in the background
    threading.Thread(target=bg_thread_func).start()

    # start flash server in the foreground or debug=True cannot be used otherwise
    # flask expects to be in the foreground
    app.run(host='0.0.0.0', port=5001, debug=False)


if __name__ == "__main__":
    main()
