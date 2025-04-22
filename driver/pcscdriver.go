// -*- Mode: Go; indent-tabs-mode: t -*-
//
// Copyright (C) 2018 Canonical Ltd
// Copyright (C) 2018-2024 IOTech Ltd
//
// SPDX-License-Identifier: Apache-2.0

// Package driver provides a simple example implementation of
// ProtocolDriver interface.
package driver

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/edgexfoundry/device-simple/client"
	"github.com/edgexfoundry/device-simple/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	"go/types"
	"reflect"
	"sync"
	"time"

	"github.com/edgexfoundry/device-sdk-go/v4/pkg/interfaces"
	sdkModels "github.com/edgexfoundry/device-sdk-go/v4/pkg/models"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/clients/logger"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos/requests"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/models"
	gometrics "github.com/rcrowley/go-metrics"
)

const operationCounterName = "OperationCounter"

type PcscDriver struct {
	sdk             interfaces.DeviceServiceSDK
	lc              logger.LoggingClient
	stopDiscovery   stopDiscoveryState
	stopProfileScan stopProfileScanState
	asyncCh         chan<- *sdkModels.AsyncValues
	deviceCh        chan<- []sdkModels.DiscoveredDevice
	//可能有并发问题
	apdu             any
	snWLock          sync.RWMutex
	serialNumberMap  map[string]string
	client           *scard.Context
	serviceConfig    *config.ServiceConfig
	operationCounter gometrics.Counter
}

type stopDiscoveryState struct {
	stop   bool
	locker sync.RWMutex
}

type stopProfileScanState struct {
	stop   map[string]bool
	locker sync.RWMutex
}

// Initialize performs protocol-specific initialization for the device
// service.
func (s *PcscDriver) Initialize(sdk interfaces.DeviceServiceSDK) error {
	s.sdk = sdk
	s.lc = sdk.LoggingClient()
	s.asyncCh = sdk.AsyncValuesChannel()
	s.deviceCh = sdk.DiscoveredDeviceChannel()
	s.serviceConfig = &config.ServiceConfig{}
	s.stopProfileScan = stopProfileScanState{stop: make(map[string]bool)}
	s.client = client.GetClient()
	s.serialNumberMap = make(map[string]string, 8)

	if err := sdk.LoadCustomConfig(s.serviceConfig, "PcscCustom"); err != nil {
		return fmt.Errorf("unable to load 'PcscCustom' custom configuration: %s", err.Error())
	}

	s.lc.Infof("Custom config is: %v", s.serviceConfig.PcscCustom)

	if err := s.serviceConfig.PcscCustom.Validate(); err != nil {
		return fmt.Errorf("'SimpleCustom' custom configuration validation failed: %s", err.Error())
	}

	if err := sdk.ListenForCustomConfigChanges(
		&s.serviceConfig.PcscCustom.Writable,
		"PcscCustom/Writable", s.ProcessCustomConfigChanges); err != nil {
		return fmt.Errorf("unable to listen for changes for 'SimpleCustom.Writable' custom configuration: %s", err.Error())
	}

	s.operationCounter = gometrics.NewCounter()

	var err error
	metricsManger := sdk.MetricsManager()
	if metricsManger != nil {
		err = metricsManger.Register(operationCounterName, s.operationCounter, nil)
	} else {
		err = errors.New("metrics manager not available")
	}

	if err != nil {
		return fmt.Errorf("unable to register metric %s: %s", operationCounterName, err.Error())
	}

	s.lc.Infof("Registered %s metric for collection when enabled", operationCounterName)

	return nil
}

// ProcessCustomConfigChanges ...
func (s *PcscDriver) ProcessCustomConfigChanges(rawWritableConfig interface{}) {
	updated, ok := rawWritableConfig.(*config.PcscWritable)
	if !ok {
		s.lc.Error("unable to process custom config updates: Can not cast raw config to type 'PcscWritable'")
		return
	}

	s.lc.Info("Received configuration updates for 'PcscCustom.Writable' section")

	previous := s.serviceConfig.PcscCustom.Writable
	s.serviceConfig.PcscCustom.Writable = *updated

	if reflect.DeepEqual(previous, *updated) {
		s.lc.Info("No changes detected")
		return
	}

	// Now check to determine what changed.
	// In this example we only have the one writable setting,
	// so the check is not really need but left here as an example.
	// Since this setting is pulled from configuration each time it is need, no extra processing is required.
	// This may not be true for all settings, such as external host connection info, which
	// may require re-establishing the connection to the external host for example.
	if previous.DiscoverSleepDurationSecs != updated.DiscoverSleepDurationSecs {
		s.lc.Infof("DiscoverSleepDurationSecs changed to: %d", updated.DiscoverSleepDurationSecs)
	}
}

// HandleReadCommands triggers a protocol Read operation for the specified device.
func (s *PcscDriver) HandleReadCommands(deviceName string, protocols map[string]models.ProtocolProperties, reqs []sdkModels.CommandRequest) (res []*sdkModels.CommandValue, err error) {

	//res = make([]*sdkModels.CommandValue, 1)
	for i, req := range reqs {
		s.lc.Debugf("PcscDriver.HandleReadCommands: protocols: %v resource: %v attributes: %v", protocols, reqs[i].DeviceResourceName, reqs[i].Attributes)
		//check Resource is existing
		_, ok := s.sdk.DeviceResource(deviceName, req.DeviceResourceName)
		if !ok {
			s.lc.Warn("Resource not found")
			return nil, errors.New("Resource not found")
		}

		var cv *sdkModels.CommandValue
		switch req.DeviceResourceName {
		case "Apdu":
			//cv, _ = sdkModels.NewCommandValue(req.DeviceResourceName, common.ValueTypeObject, s.apdus)
			card, _ := s.client.Connect(deviceName, scard.ShareExclusive, scard.ProtocolAny)
			defer card.Disconnect(scard.ResetCard)
			var cmd []byte
			switch s.apdu.(type) {
			case []byte:
				{
					cmd = s.apdu.([]byte)
				}
			}
			//todo 上线前需清除
			if cmd == nil {
				cmd = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
			}
			//cmd := []byte(s.apdu)
			//var cmd = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
			s.lc.Debugf("Transmit c-apdu: % x", cmd)
			result, err := card.Transmit(cmd)
			if err != nil {
				s.lc.Warn("Device ", deviceName, " Transmit Apdu err:", err)
			}
			s.lc.Debugf("r-apdu: % x", result)
			cv, _ = sdkModels.NewCommandValue(req.DeviceResourceName, common.ValueTypeBinary, result)
		}
		//若res最终实际为空导致无法生成event，将会导致程序空指针崩溃
		res = append(res, cv)
	}

	s.operationCounter.Inc(1)

	return
}

// HandleWriteCommands passes a slice of CommandRequest struct each representing
// a ResourceOperation for a specific device resource.
// Since the commands are actuation commands, params provide parameters for the individual
// command.
func (s *PcscDriver) HandleWriteCommands(deviceName string, protocols map[string]models.ProtocolProperties, reqs []sdkModels.CommandRequest,
	params []*sdkModels.CommandValue) error {
	var err error
	var cmds [][]byte
	var cmdsResults [][]byte

	for i, req := range reqs {
		s.lc.Debugf("PcscDriver.HandleWriteCommands: protocols: %v, resource: %v, parameters: %v, attributes: %v", protocols, reqs[i].DeviceResourceName, params[i], reqs[i].Attributes)
		//check Resource is existing
		_, ok := s.sdk.DeviceResource(deviceName, req.DeviceResourceName)
		if !ok {
			s.lc.Warn("Pcsc Resource Manager not found")
			return errors.New("Pcsc Resource Manager not found")
		}
		switch req.DeviceResourceName {
		case "Apdu":
			{
				asyncValues := &sdkModels.AsyncValues{
					DeviceName: deviceName,
				}
				if s.apdu, err = params[i].ObjectValue(); err != nil {
					s.lc.Warnf("PcscDriver.HandleWriteCommands; the data type of parameter should be Object, parameter: %s", params[i].String())
					return err
				}

				cmds, err = s.parseApdus(s.apdu)
				if err != nil {
					s.lc.Warn("parse apdus error: ", err)
					return err
				}
				if cmds == nil {
					//todo 上线前需清除
					cmds = [][]byte{{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}}
					s.lc.Warn("apdus is nil, stop execution")
					return errors.New("empty apdus")
				}
				cmdsResults = make([][]byte, len(cmds))
				//cmd := []byte(s.apdu)
				//var cmd = []byte{0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00}
				s.lc.Info("Transmit c-apdu: ", cmds)
				reader, b := s.getSerialNumberMap(deviceName)
				if b {
					card, err := s.client.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
					defer card.Disconnect(scard.ResetCard)
					if err != nil {
						s.lc.Warnf("connect with reader:%s,err:%s", reader, err)
						card.Disconnect(scard.ResetCard)
						return err
					}
					for index, cmd := range cmds {
						cmdsResults[index], err = card.Transmit(cmd)
						if err != nil {
							s.lc.Warn("Device ", deviceName, " Transmit Apdu err:", err)
							break
						}
					}
					s.lc.Info("r-apdu:", cmdsResults)
				} else {
					//todo 此处应该重新获取s.serialNumberMap的真实值更好
					s.lc.Warnf("no device:%s in devices list%s", deviceName, s.serialNumberMap)
				}
				cv, _ := sdkModels.NewCommandValue(req.DeviceResourceName, common.ValueTypeObject, cmdsResults)
				asyncValues = &sdkModels.AsyncValues{
					DeviceName:    deviceName,
					CommandValues: []*sdkModels.CommandValue{cv},
				}
				s.asyncCh <- asyncValues
			}
		}
	}

	return nil
}

// Stop the protocol-specific DS code to shutdown gracefully, or
// if the force parameter is 'true', immediately. The driver is responsible
// for closing any in-use channels, including the channel used to send async
// readings (if supported).
func (s *PcscDriver) Stop(force bool) error {
	// Then Logging Client might not be initialized
	if s.lc != nil {
		s.lc.Debugf("PcscDriver.Stop called: force=%v", force)
	}

	return s.client.Release()
}

func (s *PcscDriver) Start() error {
	return nil
}

// AddDevice is a callback function that is invoked
// when a new Device associated with this Device Service is added
func (s *PcscDriver) AddDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	s.lc.Debugf("a new Device is added: %s", deviceName)
	return nil
}

// UpdateDevice is a callback function that is invoked
// when a Device associated with this Device Service is updated
func (s *PcscDriver) UpdateDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	s.lc.Debugf("Device %s is updated", deviceName)
	return nil
}

// RemoveDevice is a callback function that is invoked
// when a Device associated with this Device Service is removed
func (s *PcscDriver) RemoveDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	s.lc.Debugf("Device %s is removed", deviceName)
	return nil
}

// Discover triggers protocol specific device discovery, which is an asynchronous operation.
// Devices found as part of this discovery operation are written to the channel devices.
func (s *PcscDriver) Discover() error {
	// Establish a context
	//涉及系统线程锁
	//获取操作系统的PCSC管理资源管理器的上下文
	s.lc.Debug("触发定时发现读卡器")
	pcscResourceManagerContext := s.client

	// List available readers
	readers, err := pcscResourceManagerContext.ListReaders()
	switch err {
	case scard.ErrSuccess:
		{
		}
	default:
		{
			ctx, err2 := scard.EstablishContext()
			if err != nil {
				s.lc.Warnf("Fail to list Readers,err:%s,and hard to recover by geting pcsc ResourceManager,err:%s", err, err2)
				return err
			}
			pcscResourceManagerContext, s.client = ctx, ctx
			readers, err2 = pcscResourceManagerContext.ListReaders()
			if err != nil {
				s.lc.Warnf("Fail to list Readers,err:%s,and  recover by geting pcsc ResourceManager successfully,but still fail to list Readers,err:%s", err, err2)
				return err2
			}
		}
	}
	s.discoverSerialNumber(readers, pcscResourceManagerContext)
	/*	fmt.Printf("Found %d readers:\n", len(readers))
		for i, reader := range readers {
			fmt.Printf("[%d] %s\n", i, reader)
		}

		if len(readers) > 0 {

			fmt.Println("Waiting for a Card")
			//获取空闲卡
			index, err := waitUntilCardPresent(pcscResourceManagerContext, readers)
			if err != nil {
				return err
			}

			// Connect to card
			fmt.Println("Connecting to card in ", readers[index])
			//card.handle所操作的智能卡的句柄
			//card.protocol该智能卡的协议
			card, err := pcscResourceManagerContext.Connect(readers[index], scard.ShareExclusive, scard.ProtocolAny)
			if err != nil {
				fmt.Println("连接卡失败", readers[index])
				return err
			}
			defer card.Disconnect(scard.ResetCard)

			fmt.Println("Card status:")
			//获取卡状态scard.CardStatus
			//reader表示当前连接的智能卡读卡器的名称
			//state：
			//SCARD_STATE_ABSENT：智能卡不在读卡器中。
			//SCARD_STATE_PRESENT：智能卡已插入读卡器。
			//SCARD_STATE_SWALLOWED：智能卡被读卡器 “吞卡”（例如，由于错误操作或安全原因）。
			//SCARD_STATE_POWERED：智能卡已上电。
			//SCARD_STATE_NEGOTIABLE：智能卡支持多种通信协议，可以进行协议协商。
			//SCARD_STATE_SPECIFIC：智能卡使用特定的通信协议。
			//activeProtocol
			//实际使用的协议
			//atr 智能卡 ATR（Answer To Reset）信息
			//这是智能卡的复位应答信息。当智能卡上电或复位时，会发送一个 ATR 字节序列，其中包含了智能卡的一些基本信息，如制造商、卡类型、支持的协议等。通过分析 ATR 信息，可以了解智能卡的特性和能力。

			status, err := card.Status()
			proto := make(map[string]models.ProtocolProperties)
			proto["pcsc"] = map[string]any{"Atr": status.Atr}

			device2 := sdkModels.DiscoveredDevice{
				Name:        status.Reader,
				Protocols:   proto,
				Description: "found by discovery",
				Labels:      []string{"auto-discovery"},
			}*/

	//res := []sdkModels.DiscoveredDevice{device2}

	//s.deviceCh <- res
	return nil

}

func (s *PcscDriver) ValidateDevice(device models.Device) error {
	protocol, ok := device.Protocols["pcsc"]
	if !ok {
		return errors.New("missing 'pcsc' protocols")
	}

	addr, ok := protocol["Atr"]
	if !ok {
		return errors.New("missing 'Atr' information")
	} else if addr == "" {
		return errors.New("Atr must not empty")
	}

	return nil
}

func (s *PcscDriver) ProfileScan(payload requests.ProfileScanRequest) (models.DeviceProfile, error) {
	time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	s.sdk.PublishProfileScanProgressSystemEvent(payload.RequestId, 50, "")
	if s.getStopProfileScan(payload.DeviceName) {
		return models.DeviceProfile{}, fmt.Errorf("profile scanning is stopped")
	}
	time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	return models.DeviceProfile{Name: payload.ProfileName}, nil
}

func (s *PcscDriver) StopDeviceDiscovery(options map[string]any) {
	s.lc.Debugf("StopDeviceDiscovery called: options=%v", options)
	s.setStopDeviceDiscovery(true)
}

func (s *PcscDriver) StopProfileScan(device string, options map[string]any) {
	s.lc.Debugf("StopProfileScan called: options=%v", options)
	s.setStopProfileScan(device, true)
}

func (s *PcscDriver) getStopDeviceDiscovery() bool {
	s.stopDiscovery.locker.RLock()
	defer s.stopDiscovery.locker.RUnlock()
	return s.stopDiscovery.stop
}

func (s *PcscDriver) setStopDeviceDiscovery(stop bool) {
	s.stopDiscovery.locker.Lock()
	defer s.stopDiscovery.locker.Unlock()
	s.stopDiscovery.stop = stop
	s.lc.Debugf("set stopDeviceDiscovery to %v", stop)
}

func (s *PcscDriver) getStopProfileScan(device string) bool {
	s.stopProfileScan.locker.RLock()
	defer s.stopProfileScan.locker.RUnlock()
	return s.stopProfileScan.stop[device]
}

func (s *PcscDriver) setStopProfileScan(device string, stop bool) {
	s.stopProfileScan.locker.Lock()
	defer s.stopProfileScan.locker.Unlock()
	s.stopProfileScan.stop[device] = stop
	s.lc.Debugf("set stopProfileScan to %v", stop)
}
func (s *PcscDriver) parseApdus(rawApdus interface{}) ([][]byte, error) {
	var cmd [][]byte
	switch rawApdus.(type) {
	case [][]byte:
		{
			cmd = rawApdus.([][]byte)
		}
	case types.Array:
		{
			apdus := rawApdus.([]interface{})
			cmd = make([][]byte, len(apdus))

			for i, apdu := range apdus {
				switch apdu.(type) {
				case []byte:
					{
						cmd[i] = apdu.([]byte)
					}
				default:
					{
						s.lc.Warnf("parse apdu meet error,apdu:%s,err:%s", rawApdus, "some type of apdu in apdus are wrong")
						return nil, errors.New("some type of apdu in apdus are wrong")
					}
				}
			}
		}
	case string:
		{
			//all := strings.ReplaceAll(rawApdus.(string), " ", "")
			//split := strings.Split(all, ",")
			//cmd = make([]byte, len(split))
			//for i2, s2 := range split {
			//	if strings.HasPrefix(s2, "0x") {
			//		temp, err := strconv.ParseUint(s2[2:], 16, 8)
			//		if err != nil {
			//			s.lc.Warnf("parse apdu meet error,apdu:%s,err:%s", apdus, err)
			//			return nil, err
			//		}
			//		cmd[i2] = uint8(temp)
			//	} else {
			//		temp, err := strconv.ParseUint(s2, 16, 8)
			//		if err != nil {
			//			s.lc.Warnf("parse apdu meet error,apdu:%s,err:%s", apdus, err)
			//			return nil, err
			//		}
			//		cmd[i2] = uint8(temp)
			//	}
			//}
			//s.lc.Debugf("parse string type apdu successfully,result:%v", cmd)
		}
	default:
		{
			s.lc.Warnf("parse apdu meet error,apdu:%s,err:%s", rawApdus, "type of apdus is not supported")
			return nil, errors.New("type of apdus is not supported")
		}
	}
	return cmd, nil

}

func (s *PcscDriver) discoverSerialNumber(readers []string, ctx *scard.Context) {
	serialNumberList := make([]string, len(readers))
	for i, reader := range readers {
		//执行命令
		card, err := ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
		//todo想要确保释放，但是万一获取sn的连接释放成功后，烧录连接连通，此时的defer把烧录的释放掉了怎么办？
		//defer card.Disconnect(scard.ResetCard)
		if err != nil {
			s.lc.Warnf("connect with reader:%s,err:%s", reader, err)
			card.Disconnect(scard.ResetCard)
			continue
		}

		//获取卡状态scard.CardStatus
		//reader表示当前连接的智能卡读卡器的名称
		//state：
		//SCARD_STATE_ABSENT：智能卡不在读卡器中。
		//SCARD_STATE_PRESENT：智能卡已插入读卡器。
		//SCARD_STATE_SWALLOWED：智能卡被读卡器 “吞卡”（例如，由于错误操作或安全原因）。
		//SCARD_STATE_POWERED：智能卡已上电。
		//SCARD_STATE_NEGOTIABLE：智能卡支持多种通信协议，可以进行协议协商。
		//SCARD_STATE_SPECIFIC：智能卡使用特定的通信协议。
		//activeProtocol
		//实际使用的协议
		//atr 智能卡 ATR（Answer To Reset）信息
		//这是智能卡的复位应答信息。当智能卡上电或复位时，会发送一个 ATR 字节序列，其中包含了智能卡的一些基本信息，如制造商、卡类型、支持的协议等。通过分析 ATR 信息，可以了解智能卡的特性和能力。

		_, err = card.Status()
		if err != nil {
			s.lc.Warnf("reader:%s status err:%s", reader, err)
			card.Disconnect(scard.ResetCard)
			continue
		}

		//读应用获取serial number
		var cmds = [][]byte{
			//选择应用
			{0x00, 0xA4, 0x04, 0x00, 0x10, 0x49, 0x4F, 0x54, 0x5F, 0x41, 0x50, 0x50, 0x4C, 0x45, 0x54, 0x5F, 0x41, 0x49, 0x44, 0x00, 0x01},
			//真正获取sn指令
			{0x80, 0x02, 0x00, 0x00, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x02},
		}
		for j, cmd := range cmds {
			s.lc.Infof("Transmit c-apdu: % x\n", cmd)
			rsp, err := card.Transmit(cmd)
			if err != nil {
				s.lc.Warnf("reader:%s Transmit apdu err:%s", reader, err)
				card.Disconnect(scard.ResetCard)
				break
			}
			s.lc.Infof("Transmit r-apdu: % x\n", rsp)
			if j == 1 {
				lenRsp := len(rsp)
				//if rsp[lenRsp-1]==0x90&&rsp[lenRsp-2]==0x00 {
				if bytes.HasSuffix(rsp, []byte{0x90, 0x00}) {
					//更新SN与reader映射，存在并发问题
					serialNumber := hex.EncodeToString(rsp[0 : lenRsp-2])
					s.setSerialNumberMap(serialNumber, reader)
					serialNumberList[i] = serialNumber
				}
			}
		}
		//fmt.Println(serialNumberMap)
		card.Disconnect(scard.ResetCard)
	}
	s.lc.Infof("the lastest devices list,%v", s.serialNumberMap)
	//此时设备要是又拔了会有问题，但是多少有点离谱
	res := make([]sdkModels.DiscoveredDevice, 0, 1)
	for _, serialNumber := range serialNumberList {
		proto := make(map[string]models.ProtocolProperties)
		proto["pcsc"] = map[string]any{"Atr": "default atr"}
		res = append(res, sdkModels.DiscoveredDevice{
			Name:        serialNumber,
			Protocols:   proto,
			Description: "found by discovery",
			Labels:      []string{"auto-discovery"}})
	}
	//todo下面3行的用来干嘛的？？？
	//time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	//PublishDeviceDiscoveryProgressSystemEvent用于发布设备发现进度的系统事件，50：表示当前设备发现的进度百分比，len(res)设备数量
	//s.sdk.PublishDeviceDiscoveryProgressSystemEvent(50, len(res), "")
	//将设备发现的停止标志设置为 false。这通常用于确保在设备发现过程结束后，设备发现功能可以继续正常工作
	defer s.setStopDeviceDiscovery(false)
	if len(res) > 0 {
		s.deviceCh <- res
	}

}
func (s *PcscDriver) setSerialNumberMap(key string, value string) {
	s.snWLock.Lock()
	s.serialNumberMap[key] = value
	s.snWLock.Unlock()
}
func (s *PcscDriver) getSerialNumberMap(key string) (string, bool) {
	s.snWLock.RLock()
	reader, ok := s.serialNumberMap[key]
	s.snWLock.RUnlock()
	return reader, ok
}
