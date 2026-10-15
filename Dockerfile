# Hugging Face Spaces (Docker SDK). Same routes/HTTP contract; ephemeral /tmp storage.
# Secrets come from Space secrets as env vars: SIGNING_KEY_PASSPHRASE, SIGNING_KEY_ENC_B64, EXPORT_TOKEN.
FROM python:3.13-slim
RUN useradd -m -u 1000 user
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --chown=user api ./api
COPY --chown=user scripts ./scripts
USER user
ENV HOST=0.0.0.0 PORT=7860 PYTHONUNBUFFERED=1 \
    SNAPSHOT_DIR=/tmp/snapshots DATA_STORE=/tmp/records SIGNING_KEY_PATH=/tmp/signing_key.enc.pem SNAPSHOT_SCHEDULER=1
EXPOSE 7860
CMD ["python", "api/index.py"]
