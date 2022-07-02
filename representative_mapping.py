from __future__ import annotations

from json import loads
from threading import Lock
from time import sleep

from requests import get


class representative_mapping:
    def __init__(self):
        self.__mutex = Lock()
        self.__representative_mappings: list[dict] = []

    def load_from_file(self, path: str):
        try:
            with open(path, encoding='utf8') as file:
                with self.__mutex:
                    self.__representative_mappings = loads(file.read())
        except FileNotFoundError:
            pass

    def load_from_url(self, url: str):
        with self.__mutex:
            self.__representative_mappings = get(url).json()

    def load_from_url_loop(self, url: str, delay_seconds: int):
        while True:
            try:
                self.load_from_url(url)
            finally:
                sleep(delay_seconds)

    def find(self, ip_address: str, port: int) -> list[dict]:
        matches = []
        with self.__mutex:
            for n in self.__representative_mappings:
                if n.get("address") == ip_address and n.get("port") == port:
                    matches.append(n.copy())

        return matches
