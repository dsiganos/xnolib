#!/bin/env python3

import flask
import threading

import peercrawler
import pynanocoin
import jsonencoder


ctx = pynanocoin.livectx
app = flask.Flask(__name__)
peerman = peercrawler.peer_manager(ctx, verbosity=1)


@app.route("/")
def main_route():
    global app, peerman

    peers = peerman.get_peers_as_list()
    js = jsonencoder.to_json(list(peers))
    return flask.Response(js, status=200, mimetype='application/json')


def bg_thread_func():
    global peerman
    # look for peers forever
    peerman.crawl(forever=True, delay=300)


def main():
    # start the peer crawler in the background
    threading.Thread(target=bg_thread_func).start()

    # start flash server in the foreground or debug=True cannot be used otherwise
    # flask expects to be in the foreground
    app.run(host='0.0.0.0', port=5000, debug=True)


if __name__ == "__main__":
    main()
