# =========================
# 构建阶段：Ubuntu 24.04 + CGO
# =========================
FROM ubuntu:24.04 AS builder
ENV DEBIAN_FRONTEND=noninteractive

ARG GO_VERSION=1.25.1
ARG GO_ARCH=amd64
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOROOT/bin:$GOPATH/bin:$PATH

ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,https://gocenter.io,https://goproxy.io,direct
ENV GOPRIVATE=gitlab.snowballtech.com

ARG UBUNTU_PKG_BASE="make git gcc g++ pkg-config wget curl ca-certificates libc6-dev"
ARG UBUNTU_PKG_EXTRA="gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf libc6-dev-arm64-cross libc6-dev-armhf-cross"
ENV TZ=Asia/Shanghai

# 安装系统依赖 + C开发库
RUN RUN echo "Types: deb\nURIs: https://mirrors.aliyun.com/ubuntu/\nSuites: noble noble-security noble-updates noble-proposed noble-backports\nComponents: main restricted universe multiverse\nSigned-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg" | tee /etc/apt/sources.list.d/aliyun.sources && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ${UBUNTU_PKG_BASE} \
        ${UBUNTU_PKG_EXTRA} \
        musl-dev \
        libpcsclite-dev \
        libpcsclite-dev:arm64 \
        libusb-1.0-0-dev:arm64 \
        libusb-1.0-0-dev \
        tzdata && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 下载并安装 Go
RUN wget -q --no-check-certificate https://mirrors.aliyun.com/golang/go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    rm -f go${GO_VERSION}.linux-${GO_ARCH}.tar.gz && \
    go version

# 构建项目
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

ARG GIT_SHA=""
# 构建多架构二进制
RUN set -eux; \
    # amd64
    GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -a -tags netgo \
        -ldflags "-extldflags '-Wl,-O2 -L/usr/lib -L/usr/local/lib -lpcsclite' -X main.gitSha=${GIT_SHA}" \
        -o /app/bin/pcsc-device-hsm.amd64 ./cmd; \
    # arm64
    GOOS=linux GOARCH=arm64 CGO_ENABLED=1 CC=aarch64-linux-gnu-gcc go build -a -tags netgo \
        -ldflags "-extldflags '-Wl,-O2 -L/usr/lib -L/usr/local/lib -lpcsclite' -X main.gitSha=${GIT_SHA}" \
        -o /app/bin/pcsc-device-hsm.arm64 ./cmd