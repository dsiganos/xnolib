import mysql.connector


def setup_db_connection(host: str = "localhost", user: str = "root",
                        passwd: str = "password123", db: str = None):
    if db is None:
        return mysql.connector.connect(host=host, user=user, passwd=passwd, auth_plugin='mysql_native_password')
    else:
        return mysql.connector.connect(host=host, user=user, passwd=passwd, database=db, auth_plugin='mysql_native_password')


def create_new_database(cursor, name: str) -> None:
    cursor.execute("CREATE DATABASE %s" % name)
    cursor.execute("USE %s" % name)
    cursor.execute("SET SQL_SAFE_UPDATES = 0")


def create_db_structure_frontier_service(cursor) -> None:
    cursor.execute("CREATE TABLE Peers (peer_id VARCHAR(36) PRIMARY KEY, ip_address VARCHAR(50), port int, score int)")
    cursor.execute("CREATE TABLE Frontiers (peer_id VARCHAR(36), frontier_hash VARCHAR(64), " +
                   "account_hash VARCHAR(64), PRIMARY KEY(peer_id, account_hash), " +
                   "FOREIGN KEY (peer_id) REFERENCES Peers(peer_id))")


def query_accounts_different_hashes(cursor):
    cursor.execute("SELECT DISTINCT f1.account_hash FROM frontiers f1 JOIN frontiers f2 " +
                   "WHERE f1.account_hash = f2.account_hash and f1.frontier_hash != f2.frontier_hash")
    return cursor
