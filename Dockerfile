FROM python:3.14-slim-bookworm AS dependencies

ENV POETRY_NO_INTERACTION=1 VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /build
RUN python -m venv /opt/venv \
    && /usr/local/bin/python -m pip install --no-cache-dir poetry==2.4.1
COPY pyproject.toml poetry.lock ./
RUN poetry install --only main --no-root

FROM python:3.14-slim-bookworm

ENV VIRTUAL_ENV=/opt/venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOAD_PROJECT_DOTENV=0
ENV PATH="/opt/venv/bin:${PATH}"
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends libmagic1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 downloadscontrol \
    && useradd --uid 10001 --gid 10001 --no-create-home downloadscontrol \
    && install -d -m 0755 -o 10001 -g 10001 /var/lib/downloadscontrol /var/lib/downloadscontrol-static \
    && install -d -m 0700 -o 10001 -g 10001 /var/lib/downloadscontrol/staging \
    && install -d -m 0755 -o 10001 -g 10001 /var/lib/downloadscontrol/approved \
    && install -m 0644 -o 10001 -g 10001 /dev/null /var/lib/downloadscontrol-static/.keep
COPY --from=dependencies /opt/venv /opt/venv
COPY --chown=10001:10001 . .
USER 10001:10001
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "2", "--threads", "2", "--timeout", "60"]
