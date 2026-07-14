FROM python:3.11-slim

# nmap (port scanning) + chromium (screenshots via Playwright, using the
# system browser instead of Playwright's own download — avoids needing
# network access to Playwright's CDN at build time) + fonts for correct
# text rendering in screenshots and the generated PDF report.
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    libcap2-bin \
    chromium \
    fonts-liberation \
    fonts-dejavu-core \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .

RUN mkdir -p /app/data /app/data/screenshots /app/data/reports

ENV CHROMIUM_PATH=/usr/bin/chromium

EXPOSE 5000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]