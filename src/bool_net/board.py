"""board.py -- in-memory stand-in for the blockchain broadcast channel.
Same API as the BroadcastChannel in the original dkg.py."""
from __future__ import annotations


class Board:
    def __init__(self) -> None:
        self.messages: list[dict] = []

    def post(self, sender, kind: str, payload) -> None:
        self.messages.append({"from": sender, "kind": kind, "payload": payload})

    def read(self, kind: str) -> list[dict]:
        return [m for m in self.messages if m["kind"] == kind]
