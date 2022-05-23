from json import loads
from typing import Any


def try_load_peers_details(path: str) -> list:
    try:
        with open(path) as file:
            contents = file.read()

        return loads(contents)

    except FileNotFoundError:
        print("Warning: file with peers details was not found.")
        return []


def get_node_details_from_id(node_id: str, node_details: list) -> dict | None:
    for i in node_details:
        try:
            if i["node_id"] == node_id:
                return i

        except KeyError:
            continue

    return None
