# ---------------------------------------------------------------------------
# Immagine Docker del client HTTP Signature
# ---------------------------------------------------------------------------
FROM python:3.11-slim

# Output non bufferizzato e nessun file .pyc nel container
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Le dipendenze vengono copiate prima del codice: se cambia solo il codice,
# Docker può riutilizzare il layer con le librerie già installate.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copio solo il codice necessario: le chiavi NON entrano nell'immagine.
# Verranno montate in sola lettura al momento del `docker run`.
COPY digest.py digit_signature.py ./

# Il client gira con un utente non privilegiato
RUN useradd --create-home --uid 10001 appuser
USER appuser

# Comando eseguito all'avvio del container
CMD ["python", "digest.py"]
