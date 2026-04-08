FROM python:3.11-slim

RUN apt update && apt install -y \
    tcpdump libcap-dev iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY nids.py .

RUN pip install scapy numpy scikit-learn

CMD ["python", "nids.py"]
