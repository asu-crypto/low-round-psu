FROM ubuntu:25.04

WORKDIR /home/ubuntu 

# Create systemd users to avoid tmpfiles.d errors
RUN groupadd -r systemd-network && useradd -r -g systemd-network systemd-network
RUN groupadd -r systemd-resolve && useradd -r -g systemd-resolve systemd-resolve
RUN groupadd -r systemd-journal && useradd -r -g systemd-journal systemd-journal

RUN apt-get update && \
    apt-get install -y \
    build-essential \
    cmake \
    libssl-dev \
    libgmp-dev \
    libboost-all-dev \
    libcrypto++-dev \
    libgmpxx4ldbl \
    libgmp10 \
    libssl3 \
    zlib1g-dev \
    git \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-dev \
    libffi-dev \
    libssl-dev \
    tcpdump \
    wget \
    iproute2 \
    linux-perf

WORKDIR /home/ubuntu
COPY ./install-dependencies.sh /home/ubuntu/install-dependencies.sh
RUN chmod +x /home/ubuntu/install-dependencies.sh
RUN /home/ubuntu/install-dependencies.sh

RUN git clone --branch v4.5.0 --depth 1 https://github.com/martinus/unordered_dense.git /home/ubuntu/unordered_dense && \
    cd /home/ubuntu/unordered_dense && mkdir build && cd build && \
    cmake .. && cmake --build . --target install

WORKDIR /home/ubuntu
RUN wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && ./llvm.sh 22

WORKDIR /home/ubuntu/src