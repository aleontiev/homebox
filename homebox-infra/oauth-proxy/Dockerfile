FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /srv
RUN pip install --no-cache-dir "fastapi>=0.115" "uvicorn[standard]>=0.30" "httpx>=0.27" "itsdangerous>=2.2"
COPY main.py /srv/main.py
EXPOSE 8000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
