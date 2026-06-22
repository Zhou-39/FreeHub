FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    python3 \
    python3-pip \
    python3-venv \
    gcc \
    g++ \
    openjdk-17-jdk \
    nodejs \
    npm \
    git \
    curl \
    wget \
    vim \
    nano \
    unzip \
    zip \
    htop \
    procps \
    sudo \
    ca-certificates \
    bash \
    && apt clean

# 创建 python 软链接
RUN ln -s /usr/bin/python3 /usr/bin/python

# 创建 coder 用户并设置权限
RUN useradd -ms /bin/bash coder && \
    echo "coder ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /home/coder && \
    chown -R coder:coder /home/coder

USER coder

# 设置 coder 用户的 PATH 和 PS1（命令行提示符）
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
ENV PS1="\u@\h:\w\$ "

WORKDIR /workspace

CMD ["/bin/bash"]
