FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY rulescope ./rulescope
COPY samples ./samples
COPY tests ./tests

RUN pip install --no-cache-dir -e .

EXPOSE 8080
CMD ["rulescope", "serve", "--host", "0.0.0.0", "--port", "8080"]
