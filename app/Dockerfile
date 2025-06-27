# Используем официальный образ Python 3.12 (slim для уменьшения размера)
FROM python:3.12-slim-bookworm

# Устанавливаем рабочую директорию в контейнере
WORKDIR /opt/vAPI/app

# Копируем файл зависимостей в контейнер
COPY requirements.txt .

# Устанавливаем зависимости
RUN pip install --no-cache-dir -r requirements.txt

# Копируем остальные файлы приложения
COPY . .

# Expose the port the app runs on
EXPOSE 8081

# Команда для запуска приложения при запуске контейнера
CMD ["/bin/bash", "-c", "python vAPI.py"]
