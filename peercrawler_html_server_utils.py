from json import loads


def try_load_peers_details(path: str) -> list:
    try:
        with open(path) as file:
            contents = file.read()

        return loads(contents)

    except FileNotFoundError:
        print("Warning: file with peers details was not found.")
        return []


def get_node_details_from_id(node_id: str, node_details: list) -> dict:
    for i in node_details:
        try:
            name = i["node_id"]

        except KeyError:
            continue
