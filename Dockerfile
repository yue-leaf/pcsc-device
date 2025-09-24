FROM ubuntu:22.04 AS builder

# 设置构建参数
ARG TARGETARCH
ARG TARGETOS=linux
ENV CGO_ENABLED=1
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

# 设置时区和必要的系统依赖
# 安装 Go 语言和构建依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    wget \
    make \
    git \
    pkg-config \
    musl-dev \
    libpcsclite-dev \
    libusb-1.0-0-dev \
    ca-certificates \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# 安装特定版本的 Go 语言
# 您可以根据需要调整 Go 版本
ENV GO_VERSION=1.23.12
RUN wget -O go.tar.gz https://golang.google.cn/dl/go${GO_VERSION}.linux-${TARGETARCH}.tar.gz && \
    tar -C /usr/local -xzf go.tar.gz && \
    rm go.tar.gz

# 设置 Go 环境变量
ENV PATH=/usr/local/go/bin:$PATH
ENV GOPATH=/go
ENV GOBIN=/go/bin

# 设置 Go 模块代理和私有仓库
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,https://gocenter.io,https://goproxy.io,direct

WORKDIR /app

# 拷贝并下载 Go 模块依赖
COPY go.mod go.sum ./
RUN go mod download

# 拷贝所有项目文件
COPY . .

# 执行构建
# -ldflags 参数用于链接 C 库
RUN go build -ldflags '-extldflags "-Wl,--verbose -L/usr/lib -L/usr/local/lib -lpcsclite"' -o ./cmd/pcsc-device-hsm.bin && chmod +x ./cmd/pcsc-device-hsm.bin

# ---------------------------------------------------------------------------------------
# 第二阶段：运行 (final)
# ---------------------------------------------------------------------------------------
FROM ubuntu:22.04

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 安装运行时依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libpcsclite1 \
    libusb-1.0-0 \
    ca-certificates \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

# 从构建阶段拷贝编译好的二进制文件
COPY --from=builder /app/cmd/pcsc-device-hsm.bin /usr/local/bin/pcsc-device-hsm

# 确保二进制文件可执行
RUN chmod +x /usr/local/bin/pcsc-device-hsm

# 容器启动时运行的命令
ENTRYPOINT ["/usr/local/bin/pcsc-device-hsm"]