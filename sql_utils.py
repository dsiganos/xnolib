import mysql.connector


def setup_db_connection(host="localhost", user="root",
                        passwd = "password123", db=None):
    if db is None:
        return mysql.connector.connect(host=host, user=user, passwd=passwd)
    else:
        return mysql.connector.connect(host=host, user=user, passwd=passwd, database=db)


def create_new_database(cursor, name="new_db"):
    cursor.execute("CREATE DATABASE %s" % name)