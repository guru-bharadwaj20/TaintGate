FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY taintgate ./taintgate
RUN python -m pip install --no-cache-dir '.[mcp,ui]' \
    && useradd --create-home --uid 10001 taintgate
USER taintgate
ENV PYTHONUNBUFFERED=1
CMD ["taintgate", "demo"]
