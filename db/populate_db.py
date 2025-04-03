import os
import psycopg2
import json

# Конфигурация БД из переменных среды
DB = {
    "user": os.getenv("POSTGRES_USER", "secweb_user"),
    "password": os.getenv("POSTGRES_PASSWORD", "secweb_pass"),
    "db": os.getenv("POSTGRES_DB", "secwebscan"),
    "host": os.getenv("POSTGRES_HOST", "secwebscan_postgres"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
}

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "config", "config.json"
)

with open(CONFIG_PATH, "r") as f:
    CONFIG = json.load(f)

PURGE_ON_START = CONFIG["proxy_management"].get("purge_on_start", False)


def connect():
    return psycopg2.connect(
        dbname=DB["db"],
        user=DB["user"],
        password=DB["password"],
        host=DB["host"],
        port=DB["port"],
    )


def purge():
    conn = connect()
    cur = conn.cursor()
    cur.execute("DELETE FROM results;")
    conn.commit()
    cur.close()
    conn.close()
    print("🗑 Очистка таблицы results завершена.")


def main():
    if PURGE_ON_START:
        purge()
    else:
        print("ℹ️ Очистка БД отключена (purge_on_start = false).")


if __name__ == "__main__":
    main()
