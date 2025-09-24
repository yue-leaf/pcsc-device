# 构建阶段：Ubuntu 24.04 + 完整C开发环境
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

ARG TARGETOS
ARG TARGETARCH

# Go版本和架构配置
ARG GO_VERSION=1.25.1
ENV GOROOT=/usr/local/go
ENV GOPATH=/go
ENV PATH=$GOPATH/bin:$GOROOT/bin:$PATH

# Go模块代理和私有仓库
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,https://gocenter.io,https://goproxy.io,direct
ENV GOPRIVATE=gitlab.snowballtech.com

# 基础参数：添加libc6-dev（C标准库开发包）
ARG UBUNTU_PKG_BASE="make git gcc g++ pkg-config wget curl ca-certificates libc6-dev"
ARG UBUNTU_PKG_EXTRA=""
ARG ADD_BUILD_TAGS=""
ARG MAKE=make build
ENV TZ=Asia/Shanghai

# 安装系统依赖（包含C开发库）
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
    sed -i s@/security.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ${UBUNTU_PKG_BASE} \
    ${UBUNTU_PKG_EXTRA} \
    musl-dev \
    libpcsclite-dev \
    libusb-1.0-0-dev \
    tzdata && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 下载并安装Go
RUN echo "Downloading Go ${GO_VERSION} (${GO_ARCH}) from aliyun..." && \
    wget -v --no-check-certificate https://mirrors.aliyun.com/golang/go${GO_VERSION}.linux-$TARGETARCH.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-$TARGETARCH.tar.gz && \
    rm -f go${GO_VERSION}.linux-$TARGETARCH.tar.gz && \
    go version && \
    go env

# 项目构建
WORKDIR /app
LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2023: Intel' \
  Name=pcsc-device-hsm Version=${VERSION}

COPY go.mod  ./
RUN go mod download all

COPY . .
RUN CGO_ENABLED=1  go build -ldflags '-extldflags "-Wl,--verbose -L/usr/lib -L/usr/local/lib -lpcsclite"' -o ./cmd/pcsc-device-hsm.bin && chmod +x ./cmd/pcsc-device-hsm.bin

# 运行阶段：Ubuntu 24.04
FROM ubuntu:22.04
LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2022: Intel'

ENV TZ=Asia/Shanghai
ENV EDGEX_SECURITY_SECRET_STORE=false

# 安装运行时依赖
RUN sed -i s@/archive.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
    sed -i s@/security.ubuntu.com/@/mirrors.aliyun.com/@g /etc/apt/sources.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    pcscd \
    libpcsclite1 \
    libusb-1.0-0 && \
    rm -rf /var/lib/apt/lists/*

# 复制构建产物
WORKDIR /pcsc-device-hsm/cmd/
COPY --from=builder /app/cmd/res ./res
COPY --from=builder /app/cmd/pcsc-device-hsm.bin ./pcsc-device-hsm.bin

# 非root用户配置
RUN groupadd -r scard && useradd -r -g scard pcsc-device-hsm && \
    chown -R pcsc-device-hsm:scard /pcsc-device-hsm

EXPOSE 59999
USER pcsc-device-hsm

ENTRYPOINT ["/pcsc-device-hsm/cmd/pcsc-device-hsm.bin"]
CMD ["-cp=keeper.http://edgex-core-keeper:59890", "--registry"]