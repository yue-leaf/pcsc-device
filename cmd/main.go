// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2017-2018 Canonical Ltd
// Copyright (C) 2018-2019 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

// This package provides a simple example of a device service.
package main

import (
	"github.com/edgexfoundry/device-sdk-go/v4"
	"github.com/edgexfoundry/device-sdk-go/v4/pkg/startup"
	"github.com/edgexfoundry/device-simple/driver"
)

const (
	serviceName string = "pcsc-device-hsm"
)

func main() {
	sd := driver.PcscDriver{}
	startup.Bootstrap(serviceName, device.Version, &sd)
}
