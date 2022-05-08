#!/bin/env python3
from flask import Flask,jsonify,request,render_template,redirect
import threading

import peercrawler
import pynanocoin
import common

app = Flask(__name__, static_url_path='/peercrawler')

ctx = pynanocoin.livectx
peerman = peercrawler.peer_manager(ctx, verbosity=1)

def bg_thread_func():
    global peerman
    # look for peers forever
    peerman.crawl(forever=True, delay=300)

@app.route("/peercrawler")
def main_website():
    global app, peerman

    peers = peerman.get_peers_copy()
    peers_copy = list(peers)

    peer_list = []
    for peer in peers_copy:
        telemetry = peer.__dict__['telemetry']
        hdr = {}
        if telemetry != None:
            if telemetry.__dict__['hdr'] == None:
                hdr['ext'] = 0
                hdr['net_id'] = 0
                hdr['ver_max'] = 0
                hdr['ver_using'] = 0
                hdr['ver_min'] = 0
                hdr['msg_type'] = 0
            else:
                hdr = telemetry.__dict__['hdr'].__dict__

            peer_list.append([peer.__dict__['ip'], peer.__dict__['port'], common.hexlify(peer.__dict__['peer_id']), peer.__dict__['is_voting'], hdr['ext'], hdr['net_id'], hdr['ver_max'], hdr['ver_using'], hdr['ver_min'], hdr['msg_type'], telemetry.__dict__['sig_verified'], common.hexlify(telemetry.__dict__['sig']), common.hexlify(telemetry.__dict__['node_id']), telemetry.__dict__['block_count'], telemetry.__dict__['cemented_count'], telemetry.__dict__['unchecked_count'], telemetry.__dict__['account_count'], telemetry.__dict__['bandwidth_cap'], telemetry.__dict__['peer_count'], telemetry.__dict__['protocol_ver'], telemetry.__dict__['uptime'], common.hexlify(telemetry.__dict__['genesis_hash']), telemetry.__dict__['major_ver'], telemetry.__dict__['minor_ver'], telemetry.__dict__['patch_ver'], telemetry.__dict__['pre_release_ver'], telemetry.__dict__['maker_ver'], telemetry.__dict__['timestamp'], telemetry.__dict__['active_difficulty'], peer.__dict__['aux'], peer.__dict__['score']])
        else:
            peer_list.append([peer.__dict__['ip'], peer.__dict__['port'], common.hexlify(peer.__dict__['peer_id']), peer.__dict__['is_voting'], "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", peer.__dict__['aux'], peer.__dict__['score']])

    return render_template('index.html', name=peer_list)

def main():
    # start the peer crawler in the background
    threading.Thread(target=bg_thread_func).start()

    # start flash server in the foreground or debug=True cannot be used otherwise
    # flask expects to be in the foreground
    app.run(port=8888)


if __name__ == "__main__":
    main()



