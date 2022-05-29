#!/bin/env python3
import time
from datetime import datetime, timedelta
import threading
from json import loads

from flask import Flask, render_template
from requests import get

import peercrawler
import pynanocoin
import common
from acctools import to_account_addr


app = Flask(__name__, static_url_path='/peercrawler')

ctx = pynanocoin.livectx
peerman = peercrawler.peer_manager(ctx, verbosity=1)
mutex = threading.Lock()


representative_mappings: list[dict]
try:
    with open("representative-mappings.json") as file:
        representative_mappings = loads(file.read())
except FileNotFoundError:
    representative_mappings = []


def bg_thread_func():
    global peerman
    # look for peers forever
    peerman.crawl(forever=True, delay=60)


def refresh_node_info():
    global representative_mappings, mutex

    try:
        with mutex:
            representative_mappings = get("https://nano.community/data/representative-mappings.json").json()
    finally:
        time.sleep(3600)


@app.route("/peercrawler")
def main_website():
    global app, peerman, representative_mappings

    peers_copy = list(peerman.get_peers_copy())

    peer_list = []
    for peer in peers_copy:
        telemetry = peer.telemetry

        if telemetry != None:
            node_id = to_account_addr(telemetry.node_id, "node_")

            node = {}
            for n in representative_mappings:
                if n.get("node_id") == node_id or n.get("address") == str(peer.ip):
                    node = n

            peer_list.append([peer.ip,
                              peer.port,
                              node.get("alias", " "),
                              node.get("account", " "),
                              peer.is_voting,
                              telemetry.sig_verified,
                              node_id,
                              telemetry.block_count,
                              telemetry.cemented_count,
                              telemetry.unchecked_count,
                              telemetry.account_count,
                              telemetry.bandwidth_cap,
                              telemetry.peer_count,
                              telemetry.protocol_ver,
                              str(timedelta(seconds=telemetry.uptime)),
                              telemetry.uptime,
                              f"{telemetry.major_ver} {telemetry.minor_ver} {telemetry.patch_ver} {telemetry.pre_release_ver} {telemetry.maker_ver}",
                              datetime.utcfromtimestamp(telemetry.timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S'),
                              telemetry.timestamp,
                              peer.score])
        else:
            peer_list.append([peer.ip,
                              peer.port,
                              "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
                              peer.score])

    return render_template('index.html', name=peer_list)


def main():
    threading.Thread(target=refresh_node_info, daemon=True).start()

    # start the peer crawler in the background
    threading.Thread(target=bg_thread_func, daemon=True).start()

    # start flash server in the foreground or debug=True cannot be used otherwise
    # flask expects to be in the foreground
    app.run(host='0.0.0.0', port=5001, debug=False)


if __name__ == "__main__":
    main()
