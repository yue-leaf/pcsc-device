#
# Copyright (c) 2023 Intel
# Copyright (c) 2024 IOTech Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#ARG BASE=golang:1.23-alpine3.20
ARG BASE=golang:1.23-alpine3.20
FROM --platform=$BUILDPLATFORM ${BASE} AS builder

# 设置 Go 模块代理
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,https://gocenter.io,https://goproxy.io,direct
ENV GOPRIVATE=gitlab.snowballtech.com

ARG ALPINE_PKG_BASE="make git"
ARG ALPINE_PKG_EXTRA=""
ARG ADD_BUILD_TAGS=""
ARG MAKE=make build

ENV TZ=Asia/Shanghai
RUN apk add --update --no-cache ${ALPINE_PKG_BASE} ${ALPINE_PKG_EXTRA}
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
        apk update && \
        apk add --no-cache git gcc musl-dev pkgconfig pcsc-lite-dev
#RUN apk add --no-cache libpcsclite-dev
WORKDIR /app

LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2023: Intel'
LABEL Name=pcsc-device-hsm Version=${VERSION}

RUN apk add --update --no-cache make git

COPY go.mod vendor* ./
RUN [ ! -d "vendor" ] && go mod download all || echo "skipping..."

COPY . .
RUN ${MAKE}
# 查看构建输出（调试用）
#RUN apk add --no-cache tree && \
#    echo "构建输出文件结构:" && \
#    tree -L 5 /app && \
#    echo "确认可执行文件位置:" && \
#    find /app -name "pcsc-device-hsm"

# Next image - Copy built Go binary into new workspace
FROM alpine:3.20
LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2022: Intel'

# 使用 Ubuntu 作为基础镜像
#FROM ubuntu:20.04

ENV TZ=Asia/Shanghai
ENV EDGEX_SECURITY_SECRET_STORE=false
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add ca-certificates tzdata pcsc-lite pcsc-lite-libs ccid && \
    rm -rf /var/cache/apk/*

#RUN apk add --update --no-cache dumb-init
## Ensure using latest versions of all installed packages to avoid any recent CVEs
#RUN apk --no-cache upgrade

WORKDIR /pcsc-device-hsm/cmd/

COPY --from=builder /app/cmd/res /pcsc-device-hsm/cmd/res
COPY --from=builder /app/cmd/pcsc-device-hsm.bin /pcsc-device-hsm/cmd/pcsc-device-hsm.bin
# 查看最终镜像的文件结构（调试用）
#RUN apk add --no-cache tree && \
#    echo "最终镜像文件结构:" && \
#    tree -L 5 /pcsc-device-hsm
#ubuntu
#RUN usermod -aG scard 2002
#alpine
RUN addgroup -S scard && adduser -S pcsc-device-hsm -G scard

EXPOSE 59999

ENTRYPOINT ["/pcsc-device-hsm/cmd/pcsc-device-hsm.bin"]
CMD ["-cp=keeper.http://edgex-core-keeper:59890", "--registry"]
