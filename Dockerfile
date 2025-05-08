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
ARG BASE=registry.cn-shanghai.aliyuncs.com/snowballtech/alpine:3.20
FROM ${BASE} AS builder

ENV TZ=Asia/Shanghai
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add ca-certificates tzdata && \
    rm -rf /var/cache/apk/*

ARG MAKE=make build

WORKDIR /device-simple

LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2023: Intel'

RUN apk add --update --no-cache make git

COPY go.mod vendor* ./
RUN [ ! -d "vendor" ] && go mod download all || echo "skipping..."

COPY . .
RUN ${MAKE}

# Next image - Copy built Go binary into new workspace
FROM registry.cn-shanghai.aliyuncs.com/snowballtech/alpine:3.20
LABEL license='SPDX-License-Identifier: Apache-2.0' \
  copyright='Copyright (c) 2022: Intel'

ENV TZ=Asia/Shanghai
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.ustc.edu.cn/g' /etc/apk/repositories && \
    apk update && \
    apk add ca-certificates tzdata && \
    rm -rf /var/cache/apk/*

#RUN apk add --update --no-cache dumb-init
## Ensure using latest versions of all installed packages to avoid any recent CVEs
#RUN apk --no-cache upgrade

WORKDIR /
COPY --from=builder /pcsc-device-hsm/cmd/Attribution.txt /Attribution.txt
COPY --from=builder /pcsc-device-hsm/cmd/device-simple /device-simple
COPY --from=builder /pcsc-device-hsm/cmd/res/ /res

EXPOSE 59999

ENTRYPOINT ["/pcsc-device-hsm"]
CMD ["-cp=consul.http://edgex-core-consul:8500", "--registry"]
