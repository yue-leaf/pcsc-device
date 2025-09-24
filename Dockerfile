# ---------------------------------------------------------------------------------------
# 第一阶段：构建 (builder)
# 使用 Go 官方镜像作为构建环境，该镜像已预装 Go 和常用的构建工具，省去了手动安装的步骤。
# ---------------------------------------------------------------------------------------
FROM golang:1.23.12-bullseye AS builder

# 设置构建参数
ARG TARGETARCH
ARG TARGETOS=linux
ENV CGO_ENABLED=1
ENV GOOS=$TARGETOS
ENV GOARCH=$TARGETARCH

# 设置时区和必要的系统依赖
# 注意：这里我们只安装构建所需的最小依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    make \
    git \
    pkg-config \
    musl-dev \
    libpcsclite-dev \
    libusb-1.0-0-dev \
    ca-certificates \
    tzdata && \
    rm -rf /var/lib/apt/lists/*

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
# 使用更小、更安全的 Debian slim 镜像作为基础，只包含运行时所需的依赖。
# ---------------------------------------------------------------------------------------
FROM debian:bullseye-slim

# 设置时区
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# 安装运行时依赖
# 这里只安装 pcsc-lite 和 libusb，这是最终程序运行所必需的。
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

# 暴露端口，如果您的应用需要
# EXPOSE 8080

# 容器启动时运行的命令
ENTRYPOINT ["/usr/local/bin/pcsc-device-hsm"]