# Container build of the Python reference (used for CI smoke tests). Same routes/HTTP contract; ephemeral /tmp storage.
# Base image pinned by digest (python:3.13-slim multi-arch index, resolved 2026-10-15); bump deliberately.
# Secrets come from env vars: SIGNING_KEY_PASSPHRASE, SIGNING_KEY_ENC_B64, EXPORT_TOKEN.
FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f
RUN useradd -m -u 1000 user
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY --chown=user api ./api
COPY --chown=user scripts ./scripts
COPY --chown=user static ./static
COPY --chown=user spec ./spec
USER user
ENV HOST=0.0.0.0 PORT=7860 PYTHONUNBUFFERED=1 \
    SNAPSHOT_DIR=/tmp/snapshots DATA_STORE=/tmp/records SIGNING_KEY_PATH=/tmp/signing_key.enc.pem SNAPSHOT_SCHEDULER=1
EXPOSE 7860
CMD ["python", "api/index.py"]
