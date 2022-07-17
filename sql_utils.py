from mysql.connector.cursor import CursorBase


def create_new_database(cursor: CursorBase, name: str) -> None:
    cursor.execute("CREATE DATABASE IF NOT EXISTS %s" % name)
    cursor.execute("USE %s" % name)


def create_db_structure_frontier_service(cursor: CursorBase) -> None:
    cursor.execute("CREATE TABLE IF NOT EXISTS Peers (peer_id VARCHAR(36) PRIMARY KEY, ip_address VARCHAR(50), port int, score int)")
    cursor.execute("CREATE TABLE IF NOT EXISTS Frontiers (peer_id VARCHAR(36), frontier_hash VARCHAR(64), " +
                   "account_hash VARCHAR(64), PRIMARY KEY(peer_id, account_hash), " +
                   "FOREIGN KEY (peer_id) REFERENCES Peers(peer_id))")


def query_accounts_different_hashes(cursor: CursorBase):
    cursor.execute("""SELECT t.account_hash FROM
    (SELECT DISTINCT account_hash, frontier_hash FROM Frontiers) t
    GROUP BY t.account_hash HAVING COUNT(t.account_hash) > 1""")
    return cursor
