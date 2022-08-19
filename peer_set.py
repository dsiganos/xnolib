from __future__ import annotations

from time import time
from typing import Iterable, Optional

import _logger
from peer import Peer


logger = _logger.get_logger()


class peer_set(set):
    def add(self, new_peer: Peer) -> None:
        assert isinstance(new_peer, Peer)

        existing = self.find(new_peer)
        if existing:
            existing.merge(new_peer)
        else:
            super(peer_set, self).add(new_peer)

    def update(self, s: Iterable[Peer]) -> None:
        for p in s:
            self.add(p)

    def find(self: set[Peer], element: Peer) -> Optional[Peer]:
        for p in self:
            if p.compare(element):
                return p

        return None

    def cleanup_inactive(self, inactivity_threshold_seconds: int):
        for peer in self.copy():
            if time() - peer.last_seen > inactivity_threshold_seconds:
                logger.debug(f"Removing inactive peer {peer}")
                self.remove(peer)
