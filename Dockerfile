FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["bash", "-c", "python rotate_keys.py rotate && uvicorn src.main:app --host 0.0.0.0 --port 8000"]