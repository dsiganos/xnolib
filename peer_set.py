from __future__ import annotations

from time import time
from typing import Iterable, Iterator, Optional

import _logger
from peer import Peer


logger = _logger.get_logger()


class peer_set:
    """
    Represents a collection of unique peers in a network. This collection is not thread-safe.
    """
    def __init__(self):
        self.__peers: set[Peer] = set()

    def add(self, new_peer: Peer) -> None:
        """
        Adds a new peer to the collection or merges it into an existing one if it's already present.
        """
        assert isinstance(new_peer, Peer)

        existing = self.find(new_peer)
        if existing:
            existing.merge(new_peer)
        else:
            self.__peers.add(new_peer)

    def remove(self, peer: Peer) -> bool:
        """
        Looks for a peer in this collection that is considered equal to the provided peer and removes it.
        Returns True if a peer was removed, False otherwise.
        """
        assert isinstance(peer, Peer)

        # try to remove by hash first, which is often faster than iterating through the set
        try:
            self.__peers.remove(peer)
            return True
        except KeyError:
            pass

        for p in self.__peers:
            if p.compare(peer):
                self.__peers.remove(p)
                return True

        return False

    def remove_exact(self, peer: Peer) -> bool:
        """
        Looks for the passed Peer instance in this collection and removes it.
        Returns True if the instance was found and removed, False otherwise.
        """
        assert isinstance(peer, Peer)

        try:
            self.__peers.remove(peer)
        except KeyError:
            return False

        return True

    def __iter__(self) -> Iterator[Peer]:
        return iter(self.__peers)

    def update(self, s: Iterable[Peer]) -> None:
        for p in s:
            self.add(p)

    def find(self, element: Peer) -> Optional[Peer]:
        """
        Looks for a peer in this collection that is considered equal to the provided peer.
        Returns a peer or None if none found.
        """
        assert isinstance(element, Peer)

        for p in self.__peers:
            if p.compare(element):
                return p

        return None

    def cleanup_inactive(self, inactivity_threshold_seconds: int) -> None:
        t = time()
        for peer in self.__peers.copy():
            if t - peer.last_seen > inactivity_threshold_seconds:
                logger.debug(f"Removing inactive peer {peer}")
                try:
                    self.__peers.remove(peer)
                except KeyError:
                    pass
