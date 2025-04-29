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

-- Удаление старой таблицы results
DROP TABLE IF EXISTS results;

-- Создание единой универсальной таблицы results
CREATE TABLE results (
    id SERIAL PRIMARY KEY,
    target TEXT NOT NULL,
    plugin TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT DEFAULT 'info',
    data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Создание индекса на поле data для ускорения поиска внутри JSONB
CREATE INDEX idx_results_data ON results USING GIN (data);

-- Создание индекса на поле plugin для ускорения выборки по типу плагина
CREATE INDEX idx_results_plugin ON results (plugin);

-- Создание индекса на поле target для ускорения выборки по целям
CREATE INDEX idx_results_target ON results (target);
