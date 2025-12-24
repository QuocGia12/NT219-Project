FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install pycryptodome
RUN pip3 install sympy

WORKDIR /lab 
COPY poc/hastad_attack /lab 

CMD ["python3", "run.py"]

