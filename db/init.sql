-- Создание пользователя, если не существует
DO $$
BEGIN
   IF NOT EXISTS (
      SELECT FROM pg_catalog.pg_roles WHERE rolname = 'secscan'
   ) THEN
      CREATE ROLE secscan LOGIN PASSWORD 'securepass';
   END IF;
END
$$;

-- Удаление устаревших таблиц
DROP TABLE IF EXISTS results;
DROP TABLE IF EXISTS nmap_results;

-- Общая таблица (если нужна)
CREATE TABLE IF NOT EXISTS results (
    id SERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    module TEXT NOT NULL,
    result_type TEXT NOT NULL,
    severity TEXT,
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Таблица под Nmap (расширенная)
CREATE TABLE IF NOT EXISTS nmap_results (
    id SERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    ip TEXT,
    hostname TEXT,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service_name TEXT,
    product TEXT,
    version TEXT,
    cpe TEXT,
    state TEXT,
    reason TEXT,
    banner TEXT,
    script_output TEXT,
    data JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);

