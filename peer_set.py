from time import time
from typing import Iterable, Optional

from pynanocoin import Peer


class peer_set(set):
    def add(self, new_peer: Peer) -> None:
        assert isinstance(new_peer, Peer)

        if new_peer in self:
            p = self.find(new_peer)
            p.last_seen = int(time())
            if not new_peer.incoming:  # the incoming property of a peer should never be set from False to True
                p.incoming = False
        else:
            super(peer_set, self).add(new_peer)

    def update(self, s: Iterable[Peer]) -> None:
        for p in s:
            self.add(p)

    def find(self, element: Peer) -> Optional[Peer]:
        for p in self:
            if element == p:
                return p

        return None

    def cleanup_inactive(self, inactivity_threshold_seconds: int, verbosity: int):
        for peer in self.copy():
            if peer.last_seen is None:
                continue

            if time() - peer.last_seen > inactivity_threshold_seconds:
                if verbosity >= 2:
                    print(f"Removing inactive peer {peer}")

                self.remove(peer)
