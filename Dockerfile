FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY rules/ ./rules/
COPY gui/ ./gui/
COPY dashboard.py .

RUN useradd -m analyzer && chown -R analyzer:analyzer /app
USER analyzer

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
