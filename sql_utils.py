import mysql.connector


def setup_db_connection(host="localhost", user="root",
                        passwd = "password123", db=None):
    if db is None:
        return mysql.connector.connect(host=host, user=user, passwd=passwd, auth_plugin='mysql_native_password')
    else:
        return mysql.connector.connect(host=host, user=user, passwd=passwd, database=db, auth_plugin='mysql_native_password')


def create_new_database(cursor, name):
    cursor.execute("CREATE DATABASE %s" % name)
    cursor.execute("USE %s" % name)


def create_db_structure_frontier_service(cursor):
    cursor.execute("CREATE TABLE Peers (peer_id VARCHAR(36) PRIMARY KEY, ip_address VARCHAR(50), port int, score int)")
    cursor.execute("CREATE TABLE Frontiers (frontier_id int PRIMARY KEY AUTO_INCREMENT, peer_id VARCHAR(36), " +
                   "frontier_hash VARCHAR(64), account VARCHAR(64), " +
                   "FOREIGN KEY(peer_id) REFERENCES Peers(peer_id))")