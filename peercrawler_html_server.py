#!/bin/env python3

from __future__ import annotations

from datetime import datetime, timedelta
import threading

from flask import Flask, Response, render_template

import jsonencoder
import peercrawler
import pynanocoin
from acctools import to_account_addr
from representative_mapping import representative_mapping
from _logger import setup_logger, get_logger


app = Flask(__name__, static_url_path='/peercrawler')
logger = get_logger()

ctx = pynanocoin.livectx
peerman = peercrawler.peer_manager(ctx, verbosity=1)

representatives = representative_mapping()
representatives.load_from_file("representative-mappings.json")
threading.Thread(target=representatives.load_from_url_loop, args=("https://nano.community/data/representative-mappings.json", 3600), daemon=True).start()


def bg_thread_func():
    global peerman
    # look for peers forever
    peerman.crawl(forever=True, delay=60)


@app.route("/peercrawler")
def main_website():
    global app, peerman, representatives

    peers_copy = list(peerman.get_peers_copy())

    peer_list = []
    for peer in peers_copy:
        telemetry = peer.telemetry

        if telemetry != None:
            node_id = to_account_addr(telemetry.node_id, "node_")

            representative_info = representatives.find(node_id, str(peer.ip))
            aliases = [r.get("alias", " ") for r in representative_info]
            accounts = [r.get("account", " ") for r in representative_info]
            weights = [r.get("weight", " ") for r in representative_info]

            peer_list.append([peer.ip,
                              peer.port,
                              " // ".join(filter(lambda n: isinstance(n, str), aliases)),  # filter out None values
                              filter(lambda n: isinstance(n, str), accounts),
                              peer.is_voting,
                              telemetry.sig_verified,
                              peer.incoming,
                              node_id,
                              " // ".join(filter(lambda n: n is not None, weights)),
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


@app.route("/peercrawler/json")
def json():
    global app, peerman

    peers = peerman.get_peers_copy()
    js = jsonencoder.to_json(list(peers))
    return Response(js, status=200, mimetype="application/json")


@app.route("/peercrawler/logs")
def logs():
    log_file_name = "peercrawler.log"

    try:
        with open(log_file_name + ".1", mode="r", encoding="UTF-8") as f:
            log_1 = f.read()
    except FileNotFoundError:
        log_1 = ""

    try:
        with open(log_file_name, mode="r") as f:
            log_2 = f.read()
    except FileNotFoundError:
        log_2 = ""

    return Response(log_1 + log_2, status=200, mimetype="text/plain")


def main():
    setup_logger(logger)

    # start the peer crawler in the background
    threading.Thread(target=bg_thread_func, daemon=True).start()

    # start flash server in the foreground or debug=True cannot be used otherwise
    # flask expects to be in the foreground
    app.run(host='0.0.0.0', port=5001, debug=False)


if __name__ == "__main__":
    main()
