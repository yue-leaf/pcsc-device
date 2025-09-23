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
FROM ${BASE} AS builder

# 设置 Go 模块代理
ENV GO111MODULE=on
ENV GOPROXY=https://goproxy.cn,https://gocenter.io,https://goproxy.io,direct
ENV GOPRIVATE=gitlab.snowballtech.com

ARG ALPINE_PKG_BASE="make git"
ARG ALPINE_PKG_EXTRA=""
ARG ADD_BUILD_TAGS=""
ARG MAKE=make build

ENV TZ=Asia/Shanghai

# 修正1：先替换镜像源，再安装包（顺序很重要！）
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache ${ALPINE_PKG_BASE} ${ALPINE_PKG_EXTRA} git gcc musl-dev pkgconfig pcsc-lite-dev

WORKDIR /app

LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2023: Intel'
LABEL Name=pcsc-device-hsm Version=${VERSION}

COPY go.mod vendor* ./
RUN [ ! -d "vendor" ] && go mod download all || echo "skipping..."

COPY . .
RUN ${MAKE}

# Next image - Copy built Go binary into new workspace
FROM alpine:3.20
LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2022: Intel'

ENV TZ=Asia/Shanghai
ENV EDGEX_SECURITY_SECRET_STORE=false

# 修正2：在最终镜像中也正确替换镜像源
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && \
    apk update && \
    apk add --no-cache ca-certificates tzdata pcsc-lite pcsc-lite-libs ccid && \
    rm -rf /var/cache/apk/*

WORKDIR /pcsc-device-hsm/cmd/

COPY --from=builder /app/cmd/res /pcsc-device-hsm/cmd/res
COPY --from=builder /app/cmd/pcsc-device-hsm.bin /pcsc-device-hsm/cmd/pcsc-device-hsm.bin

# 修正3：创建用户和组
RUN addgroup -S scard && adduser -S pcsc-device-hsm -G scard

# 修正4：确保可执行文件有执行权限
RUN chmod +x /pcsc-device-hsm/cmd/pcsc-device-hsm.bin

EXPOSE 59999

ENTRYPOINT ["/pcsc-device-hsm/cmd/pcsc-device-hsm.bin"]
CMD ["-cp=keeper.http://edgex-core-keeper:59890", "--registry"]