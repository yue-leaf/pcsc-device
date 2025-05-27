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
	//pprof时需要
	//_ "net/http/pprof"
)

const (
	serviceName string = "pcsc-device-hsm"
)

func main() {
	//pprof时需要
	//go func() {
	//	http.ListenAndServe("localhost:6060", nil)
	//}()
	//锁阻塞分析
	//runtime.SetBlockProfileRate(100)
	//锁竞争分析
	//runtime.SetMutexProfileFraction(1)
	sd := driver.PcscDriver{}
	startup.Bootstrap(serviceName, device.Version, &sd)
}
