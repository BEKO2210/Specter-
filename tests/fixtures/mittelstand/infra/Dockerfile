# ABSICHTLICH VERWUNDBAR - Test-Fixture. Veraltetes Basis-Image.
FROM python:2.7

# Veraltete, unsichere Bibliotheken
RUN pip install django==1.8 requests==2.6.0

COPY . /app
WORKDIR /app

# Laeuft als root
CMD ["python", "service.py"]
