# --- Stage 1: Build the React Frontend ---
FROM node:20-slim AS frontend-builder
WORKDIR /build

# Copy frontend source
COPY frontend/package*.json ./
RUN npm install --silent
COPY frontend/ ./

# Build the frontend (creates 'dist' folder)
RUN npm run build

# --- Stage 2: Final Production Container ---
FROM python:3.10-slim
WORKDIR /app

# Install system dependencies (needed for MySQL, PostgreSQL, and LDAP)
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    libpq-dev \
    libldap2-dev \
    libsasl2-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python backend dependencies
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy backend source. See .dockerignore — .env and data/ are excluded so
# secrets are not baked into the image layers.
COPY . /app

# Copy the built frontend from the previous stage
# Note: Since app.py now expects ./frontend/dist
RUN mkdir -p /app/frontend/dist
COPY --from=frontend-builder /build/dist /app/frontend/dist

# Environment variables
ENV PYTHONUNBUFFERED=1
ENV VITE_API_BASE_URL=""
# Empty, not "*": the SPA is served from this same container, so requests are
# same-origin. A wildcard origin is rejected by browsers once the session
# cookie is attached.
ENV CORS_ORIGINS=""

# Drop root. The container previously ran as uid 0, so any code execution bug
# in the API — the HTTP proxy and the playbook engine both reach out to
# attacker-influenced input — started with full privileges inside the
# container. /app/data is the one path written at runtime (the Fernet key when
# FERNET_KEY is unset), so it is the only thing the app user needs to own.
RUN useradd --system --create-home --uid 10001 sentora \
    && mkdir -p /app/data \
    && chown -R sentora:sentora /app/data \
    && chmod 700 /app/data
USER sentora

# Expose Sanic port
EXPOSE 8000

# Start command
# Default to running the main app (API + UI)
CMD ["python", "app.py"]
