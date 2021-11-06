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

    peers = peerman.get_peers_copy()
    js = jsonencoder.to_json(list(peers))
    return flask.Response(js, status=200, mimetype='application/json')


def rest_thread_func():
    global app
    app.run(host='0.0.0.0', port=5000)


def main():
    # start the REST server in the background
    threading.Thread(target=rest_thread_func).start()

    # look for peers forever
    peerman.crawl(forever=True, delay=300)

if __name__ == "__main__":
    main()
