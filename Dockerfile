# Warrant API container.
FROM python:3.14-slim

# uv for fast, reproducible dependency installation.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Install dependencies first (cached layer) from the lockfile.
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN uv sync --frozen --no-dev

# App code and data the runtime reads.
COPY corpus ./corpus
COPY evals ./evals
COPY fixtures ./fixtures

EXPOSE 8000

# GROQ_API_KEY must be provided at runtime:
#   docker run -e GROQ_API_KEY=... -p 8000:8000 warrant
CMD ["uv", "run", "uvicorn", "warrant.api:app", "--host", "0.0.0.0", "--port", "8000"]
