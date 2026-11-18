# Intentionally vulnerable — local lab only. See WARNING.md.
FROM python:3.12-slim

WORKDIR /app
COPY brokenshop ./brokenshop
COPY docs ./docs
COPY README.md WARNING.md LICENSE ./

# Fresh database on every container start.
ENV BROKENSHOP_RESET=1 \
    PYTHONUNBUFFERED=1

EXPOSE 8000
CMD ["python", "-m", "brokenshop", "--host", "0.0.0.0", "--port", "8000"]
