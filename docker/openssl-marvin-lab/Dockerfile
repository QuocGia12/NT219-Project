FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    wget make gcc perl ca-certificates python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src

# Build OpenSSL vulnerable 1.1.1q
RUN wget https://www.openssl.org/source/old/1.1.1/openssl-1.1.1q.tar.gz \
    && tar -zxf openssl-1.1.1q.tar.gz

WORKDIR /usr/src/openssl-1.1.1q
RUN ./config no-shared --prefix=/opt/openssl-vuln --openssldir=/opt/openssl-vuln \
    && make \
    && make install

# Back to /app
WORKDIR /app

# Generate RSA key
RUN /opt/openssl-vuln/bin/openssl req -x509 -newkey rsa:1024 \
    -keyout private.key -out cert.pem -nodes -days 365 \
    -subj "/CN=localhost"

# Ensure permissions
RUN chmod 600 private.key

# Copy server
COPY server_oracle.py /app/server_oracle.py
RUN chmod +x /app/server_oracle.py

EXPOSE 9999

CMD ["python3", "/app/server_oracle.py"]
