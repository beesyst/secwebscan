FROM postgres:17.4

# Переменные окружения
ENV POSTGRES_USER=secweb_user
ENV POSTGRES_PASSWORD=secweb_pass
ENV POSTGRES_DB=beescan

# Инициализация базы
COPY init.sql /docker-entrypoint-initdb.d/
