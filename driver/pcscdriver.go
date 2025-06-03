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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ebfe/scard"
	"github.com/edgexfoundry/device-simple/log"
	"github.com/edgexfoundry/device-simple/usafecard"
	"github.com/rs/zerolog"

	//"github.com/edgexfoundry/device-sdk-go/v4/internal/cache"
	"github.com/edgexfoundry/device-sdk-go/v4/pkg/interfaces"
	sdkModels "github.com/edgexfoundry/device-sdk-go/v4/pkg/models"
	"github.com/edgexfoundry/device-simple/client"
	"github.com/edgexfoundry/device-simple/config"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/common"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/dtos/requests"
	"github.com/edgexfoundry/go-mod-core-contracts/v4/models"
	gometrics "github.com/rcrowley/go-metrics"
	"reflect"
	"strings"
	"sync"
	"time"
)

const operationCounterName = "OperationCounter"

type PcscDriver struct {
	sdk interfaces.DeviceServiceSDK
	//lc              logger.LoggingClient
	lc              *zerolog.Logger
	stopDiscovery   stopDiscoveryState
	stopProfileScan stopProfileScanState
	asyncCh         chan<- *sdkModels.AsyncValues       //框架自带，异步事件通知，可借此主动发送异步通知，可通过订阅mqtt的topic消费，topicName见框架的utils.SendEvent方法中
	deviceCh        chan<- []sdkModels.DiscoveredDevice //框架自带，用于向框架（metadata）传递发现的新设备
	readerCh        map[string]chan struct{}            //reader的轻量锁，通过管道传递可用reader，目的是解决Discover与执行业务请求，业务请求与业务请求间存在并发的通过reader获取card连接失败，导致出现card为nil值的问题
	//可能有并发问题
	apdu                  any                            //接收下游服务的请求参数（当前定义为json格式 Apdu:{Apdu:[][]byte,RequestId:""}）
	snWLock               sync.RWMutex                   //serialNumberReaderMap的专用锁snWLock
	serialNumberReaderMap map[string]usafecard.USafeCard //serialNumber为U-Safe内实例的唯一id，作为框架内的deviceName传递，Reader是操控读卡器的句柄，serialNumberReaderMap管理SN与读卡器名reader的映射关系
	client                *scard.Context
	serviceConfig         *config.ServiceConfig
	operationCounter      gometrics.Counter
}

const (
	READY = iota
	Connecting
)

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

	s.asyncCh = sdk.AsyncValuesChannel()
	s.deviceCh = sdk.DiscoveredDeviceChannel()
	s.readerCh = make(map[string]chan struct{}, 8)
	s.serviceConfig = &config.ServiceConfig{}
	s.stopProfileScan = stopProfileScanState{stop: make(map[string]bool)}
	s.client = client.GetClient()
	s.serialNumberReaderMap = make(map[string]usafecard.USafeCard, 8)

	if err := sdk.LoadCustomConfig(s.serviceConfig, "PcscCustom"); err != nil {
		return fmt.Errorf("unable to load 'PcscCustom' custom configuration: %s", err.Error())
	}
	customConfig := s.serviceConfig.PcscCustom
	fmt.Println("Custom config is: ", customConfig)
	//s.lc.Infof("Custom config is: %v", customConfig)

	if err := customConfig.Validate(); err != nil {
		return fmt.Errorf("'SimpleCustom' custom configuration validation failed: %s", err.Error())
	}

	if err := sdk.ListenForCustomConfigChanges(
		&customConfig.Writable,
		"PcscCustom/Writable", s.ProcessCustomConfigChanges); err != nil {
		return fmt.Errorf("unable to listen for changes for 'SimpleCustom.Writable' custom configuration: %s", err.Error())
	}
	log.InitLogger(log.LogConfig{
		SourceType:    customConfig.LogConfig.SourceType,
		LogFile:       customConfig.LogConfig.LogFile,
		LogDir:        customConfig.LogConfig.LogDir,
		Encrypted:     customConfig.LogConfig.Encrypted,
		OutputConsole: customConfig.LogConfig.OutputConsole,
		MinLevel:      customConfig.LogConfig.MinLevel,
	})
	s.lc = log.GetLogger()
	//s.lc = sdk.LoggingClient()
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

	s.lc.Info().Msgf("Registered %s metric for collection when enabled", operationCounterName)

	return nil
}

// ProcessCustomConfigChanges ...
func (s *PcscDriver) ProcessCustomConfigChanges(rawWritableConfig interface{}) {
	edgeXLog := log.NewEdgeXLog(s.lc)
	updated, ok := rawWritableConfig.(*config.PcscWritable)
	if !ok {
		edgeXLog.Error("unable to process custom config updates: Can not cast raw config to type 'PcscWritable'")
		return
	}

	edgeXLog.Info("Received configuration updates for 'PcscCustom.Writable' section")

	previous := s.serviceConfig.PcscCustom.Writable
	s.serviceConfig.PcscCustom.Writable = *updated

	if reflect.DeepEqual(previous, *updated) {
		edgeXLog.Info("No changes detected")
		return
	}

	// Now check to determine what changed.
	// In this example we only have the one writable setting,
	// so the check is not really need but left here as an example.
	// Since this setting is pulled from configuration each time it is need, no extra processing is required.
	// This may not be true for all settings, such as external host connection info, which
	// may require re-establishing the connection to the external host for example.
	if previous.DiscoverSleepDurationSecs != updated.DiscoverSleepDurationSecs {
		edgeXLog.Infof("DiscoverSleepDurationSecs changed to: %d", updated.DiscoverSleepDurationSecs)
	}
}

// HandleReadCommands triggers a protocol Read operation for the specified device.
func (s *PcscDriver) HandleReadCommands(deviceName string, protocols map[string]models.ProtocolProperties, reqs []sdkModels.CommandRequest) (res []*sdkModels.CommandValue, err error) {
	//res = make([]*sdkModels.CommandValue, 1)
	for i, req := range reqs {
		edgeXLog := log.NewEdgeXLog(s.lc)
		edgeXLog.Debugf("PcscDriver.HandleReadCommands: protocols: %v resource: %v attributes: %v", protocols, reqs[i].DeviceResourceName, reqs[i].Attributes)
		//check Resource is existing
		_, ok := s.sdk.DeviceResource(deviceName, req.DeviceResourceName)
		if !ok {
			edgeXLog.Warn("Resource not found")
			return nil, errors.New("resource not found")
		}

		var cv *sdkModels.CommandValue
		switch req.DeviceResourceName {
		case "Apdu":
			{
				currCard, b := s.getSerialNumberMap(deviceName)
				if b {
					//通过轻量锁控制实现
					card := s.getReadyCard(&edgeXLog, currCard.Reader, s.client)
					if card == nil {
						edgeXLog.Warnf("get ready card fail,reader:%v", currCard.Reader)
						s.putReadyCard(&edgeXLog, currCard.Reader, card)
						return nil, errors.New("get no ready card")
					}

					var cmd []byte
					switch s.apdu.(type) {
					case []byte:
						{
							cmd = s.apdu.([]byte)
						}
					}
					if cmd == nil {
						edgeXLog.Warn("apdus is nil, stop execution")
						return nil, errors.New("empty apdus")
					}
					edgeXLog.Debugf("Transmit c-apdu: %x", cmd)
					result, err := card.Transmit(cmd)
					if err != nil {
						edgeXLog.Warnf("Device %s Transmit Apdu err:%v", deviceName, err)
					}
					edgeXLog.Debugf("r-apdu: %x", result)
					cv, _ = sdkModels.NewCommandValue(req.DeviceResourceName, common.ValueTypeBinary, result)
				} else {
					all := s.getAllSerialNumberReaderMap()
					edgeXLog.Warnf("no device:%s in devices readers Map%s", deviceName, all)
					return nil, errors.New("no reader in devices readers Map")
				}
			}
		default:
			{
				edgeXLog.Warnf("no such DeviceResourceName%s", req.DeviceResourceName)
				return nil, errors.New("no such DeviceResourceName")
			}

		}
		//若res最终实际为空导致无法生成event，将会导致程序空指针崩溃，todo需沟通如何传递DeviceResourceName值不支持的情况，指令解析异常的情况，
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
	var apdu any
	var reqBody apduReqBody
	var cmds [][]byte
	var cmdsResults [][]byte
	//t1 := time.Now()
	for i, req := range reqs {
		edgeXLog := log.NewEdgeXLog(s.lc)
		edgeXLog.Infof("get request:%v", req)
		//lc := log.GetLoggerWithTrace(reqBody.RequestId)
		//lc := s.lc.Hook(edgeXLog).With().Logger()

		edgeXLog.Debugf("PcscDriver.HandleWriteCommands: protocols: %v, resource: %v, parameters: %v, attributes: %v", protocols, reqs[i].DeviceResourceName, params[i], reqs[i].Attributes)
		//check Resource is existing
		_, ok := s.sdk.DeviceResource(deviceName, req.DeviceResourceName)
		if !ok {
			edgeXLog.Warn("Pcsc Resource Manager not found")
			return errors.New("pcsc Resource Manager not found")
		}
		switch req.DeviceResourceName {
		case "Apdu":
			{
				asyncValues := &sdkModels.AsyncValues{
					DeviceName: deviceName,
				}

				if apdu, err = params[i].ObjectValue(); err != nil {
					edgeXLog.Warnf("PcscDriver.HandleWriteCommands; the data type of parameter should be Object, parameter: %s", params[i].String())
					return err
				}
				reqBody, err = s.parseApdus(&edgeXLog, apdu)
				edgeXLog.TraceId = reqBody.RequestId
				edgeXLog.Infof("receive RequestId:%s", reqBody.RequestId)
				if err != nil {
					edgeXLog.Warnf("parse apdus error: %s", err)
					return err
				}
				cmds = reqBody.Apdu
				if cmds == nil {
					edgeXLog.Warn("apdus is nil, stop execution")
					return errors.New("empty apdus")
				}
				edgeXLog.Infof("Transmit c-apdu:%x ", cmds)
				currCard, b := s.getSerialNumberMap(deviceName)
				if b {
					//通过轻量锁控制实现
					card := s.getReadyCard(&edgeXLog, currCard.Reader, s.client)
					if card == nil {
						edgeXLog.Warnf("RequestId:%s,get ready card fail", reqBody.RequestId)
						s.putReadyCard(&edgeXLog, currCard.Reader, card)
						return errors.New("get no ready card")
					}
					cmdsResults = make([][]byte, len(cmds))
					for index, cmd := range cmds {
						result, err := card.Transmit(cmd)
						//cmdsResults[index] = make([]byte, len(result))
						cmdsResults[index] = result
						if err != nil {
							edgeXLog.Warnf("Device %s Transmit Apdu err:%v", deviceName, err)
							break
						}
					}
					//通过轻量锁控制实现
					//todo部分情况下释放似乎很耗时
					s.putReadyCard(&edgeXLog, currCard.Reader, card)
					//原实现
					//closeCardConnection(card)
					edgeXLog.Infof("r-apdu:%x", cmdsResults)
				} else {
					all := s.getAllSerialNumberReaderMap()
					edgeXLog.Warnf("no device:%s in devices readers Map%s", deviceName, all)
					return errors.New("no reader in devices readers Map")
				}
				result := map[string]interface{}{
					"ApduResult": cmdsResults,
					"RequestId":  edgeXLog.TraceId,
				}
				cv, _ := sdkModels.NewCommandValue(req.DeviceResourceName, common.ValueTypeObject, result)
				asyncValues = &sdkModels.AsyncValues{
					DeviceName:    deviceName,
					CommandValues: []*sdkModels.CommandValue{cv},
				}
				s.asyncCh <- asyncValues
			}
		default:
			{
				edgeXLog.Warnf("no such DeviceResourceName%s", req.DeviceResourceName)
				return errors.New("no such DeviceResourceName")
			}
		}
	}
	//fmt.Println("总耗时：", time.Now().Sub(t1))
	return nil
}

// Stop the protocol-specific DS code to shutdown gracefully, or
// if the force parameter is 'true', immediately. The driver is responsible
// for closing any in-use channels, including the channel used to send async
// readings (if supported).
func (s *PcscDriver) Stop(force bool) error {
	edgeXLog := log.NewEdgeXLog(s.lc)
	// Then Logging Client might not be initialized
	if s.lc != nil {
		edgeXLog.Warnf("PcscDriver.Stop called: force=%v", force)
	}
	oldserialNumberReaderMap := s.getAllSerialNumberReaderMap()
	edgeXLog.Info("modify all devices to down")
	s.deleteOldDevice(&edgeXLog, oldserialNumberReaderMap, []string{})
	log.Close()
	return s.client.Release()
}

func (s *PcscDriver) Start() error {
	return nil
}

// AddDevice is a callback function that is invoked
// when a new Device associated with this Device Service is added
// MetadataSystemEventsCallback中监听messagebus中的DeviceSystemEventType
func (s *PcscDriver) AddDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	edgeXLog := log.NewEdgeXLog(s.lc)
	edgeXLog.Infof("a new Device is added: %s", deviceName)
	return nil
}

// UpdateDevice is a callback function that is invoked
// when a Device associated with this Device Service is updated
// MetadataSystemEventsCallback中监听messagebus中的DeviceSystemEventType
func (s *PcscDriver) UpdateDevice(deviceName string, protocols map[string]models.ProtocolProperties, adminState models.AdminState) error {
	edgeXLog := log.NewEdgeXLog(s.lc)
	edgeXLog.Infof("Device %s is updated", deviceName)
	return nil
}

// RemoveDevice is a callback function that is invoked
// when a Device associated with this Device Service is removed
// MetadataSystemEventsCallback中监听messagebus中的DeviceSystemEventType
func (s *PcscDriver) RemoveDevice(deviceName string, protocols map[string]models.ProtocolProperties) error {
	edgeXLog := log.NewEdgeXLog(s.lc)
	edgeXLog.Infof("Device %s is removed", deviceName)
	return nil
}

// Discover triggers protocol specific device discovery, which is an asynchronous operation.
// Devices found as part of this discovery operation are written to the channel devices.
func (s *PcscDriver) Discover() error {
	edgeXLog := log.NewEdgeXLog(s.lc)
	//edgeXLog.TraceId = "TraceIdadadasd"
	// Establish a context
	//涉及系统线程锁
	//获取操作系统的PCSC管理资源管理器的上下文
	edgeXLog.Debug("触发定时发现读卡器")
	pcscResourceManagerContext := s.client

	// List available readers
	readers, err := pcscResourceManagerContext.ListReaders()
	switch err {
	case scard.ErrSuccess, nil:
		{
		}
		//没有获取到设备的情况交给发现设备逻辑自动移除旧设备
	case scard.ErrNoReadersAvailable:
		{

		}
	default:
		{
			ctx, err2 := scard.EstablishContext()
			if err2 != nil {
				edgeXLog.Warnf("Fail to list Readers,err:%s,and hard to recover by getting pcsc ResourceManager,err:%s", err, err2)
				oldserialNumberReaderMap := s.getAllSerialNumberReaderMap()
				edgeXLog.Info("modify all devices to down")
				s.deleteOldDevice(&edgeXLog, oldserialNumberReaderMap, []string{})
				return err
			}
			pcscResourceManagerContext, s.client = ctx, ctx
			readers, err2 = pcscResourceManagerContext.ListReaders()
			if err != nil {
				edgeXLog.Warnf("Fail to list Readers,err:%s,and  recover by getting pcsc ResourceManager successfully,but still fail to list Readers,err:%s", err, err2)
				oldserialNumberReaderMap := s.getAllSerialNumberReaderMap()
				edgeXLog.Info("modify all devices to down")
				s.deleteOldDevice(&edgeXLog, oldserialNumberReaderMap, []string{})
				return err2
			}
		}
	}
	edgeXLog.Infof("find readers:%v", readers)
	//通过readerCh作为轻量锁，来传递reader是否可用
	for _, reader := range readers {
		if _, ok := s.readerCh[reader]; !ok {
			s.readerCh[reader] = make(chan struct{}, 1)
			s.readerCh[reader] <- struct{}{}
		}
	}
	//todo还需做到设备拔除后通知metadata，防止下游获取到不可用设备
	s.discoverSerialNumber(&edgeXLog, readers, pcscResourceManagerContext)
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
			defer closeCardConnection(card)

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
	pcsc, ok := device.Protocols["pcsc"]
	if !ok {
		return errors.New("missing 'pcsc' protocols")
	}
	if pcsc["SerialNumber"] == "" {
		return errors.New("missing 'SerialNumber'")
	}

	return nil
}

func (s *PcscDriver) ProfileScan(payload requests.ProfileScanRequest) (models.DeviceProfile, error) {
	time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	s.sdk.PublishProfileScanProgressSystemEvent(payload.RequestId, 50, "")
	edgeXLog := log.NewEdgeXLog(s.lc)
	if s.getStopProfileScan(payload.DeviceName) {
		edgeXLog.Error("profile scanning is stopped")
		return models.DeviceProfile{}, errors.New("profile scanning is stopped")
	}
	time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	return models.DeviceProfile{Name: payload.ProfileName}, nil
}

func (s *PcscDriver) StopDeviceDiscovery(options map[string]any) {
	edgeXLog := log.NewEdgeXLog(s.lc)
	edgeXLog.Infof("StopDeviceDiscovery called: options=%v", options)
	s.setStopDeviceDiscovery(true)
}

func (s *PcscDriver) StopProfileScan(device string, options map[string]any) {
	edgeXLog := log.NewEdgeXLog(s.lc)
	edgeXLog.Infof("StopProfileScan called: options=%v", options)
	s.setStopProfileScan(device, true)
}

func (s *PcscDriver) getStopDeviceDiscovery() bool {

	s.stopDiscovery.locker.RLock()
	defer s.stopDiscovery.locker.RUnlock()
	return s.stopDiscovery.stop
}

func (s *PcscDriver) setStopDeviceDiscovery(stop bool) {
	edgeXLog := log.NewEdgeXLog(s.lc)
	s.stopDiscovery.locker.Lock()
	defer s.stopDiscovery.locker.Unlock()
	s.stopDiscovery.stop = stop
	edgeXLog.Infof("set stopDeviceDiscovery to %v", stop)
}

func (s *PcscDriver) getStopProfileScan(device string) bool {
	s.stopProfileScan.locker.RLock()
	defer s.stopProfileScan.locker.RUnlock()
	return s.stopProfileScan.stop[device]
}

func (s *PcscDriver) setStopProfileScan(device string, stop bool) {
	edgeXLog := log.NewEdgeXLog(s.lc)
	s.stopProfileScan.locker.Lock()
	defer s.stopProfileScan.locker.Unlock()
	s.stopProfileScan.stop[device] = stop
	edgeXLog.Infof("set stopProfileScan to %v", stop)
}

type apduReqBody struct {
	Apdu      [][]byte `json:"Apdu"`
	RequestId string   `json:"RequestId"`
}

func (s *PcscDriver) parseApdus(edgeXLog *log.EdgeXLogHook, rawApdus interface{}) (apduReqBody, error) {
	var temp apduReqBody
	//var cmd [][]byte
	switch t := rawApdus.(type) {
	/*	case [][]byte:
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


		case []interface{}:
			{
				rawApduArray := rawApdus.([]interface{})
				cmd = make([][]byte, len(rawApduArray))
				for i, raw := range rawApduArray {
					decodeString, _ := base64.StdEncoding.DecodeString(raw.(string))
					cmd[i] = decodeString
					//hexStr := hex.EncodeToString(decodeString)
					//hex.DecodeString()
				}
				//base64.StdEncoding.DecodeString()
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
			}*/
	case string:
		{

			raw := rawApdus.(string)
			body, _ := base64.StdEncoding.DecodeString(raw)

			if err := json.Unmarshal(body, &temp); err != nil {
				edgeXLog.Warnf("Unmarshal body meet error,body:%v,err:%s", body, err)
				return temp, err
			}
			//cmd = make([][]byte, len(temp.Apdu))
			//for i, rawApdu := range temp.Apdu {
			//	decodeString, _ := base64.StdEncoding.DecodeString(string(rawApdu))
			//	cmd[i] = decodeString
			//}
			//temp.Apdu = cmd
		}
	default:
		{
			typeOf := reflect.TypeOf(rawApdus)

			edgeXLog.Warnf("rawApdus typeOf:%v,typeOf.Elem():%v", typeOf, typeOf.Elem())
			edgeXLog.Warnf("parse apdu meet error,apdu:%v,apdu-type:%v,err:%s", t, typeOf, "type of apdus is not supported")
			return temp, errors.New("type of apdus is not supported")
		}
	}
	return temp, nil

}

func (s *PcscDriver) discoverSerialNumber(edgeXLog *log.EdgeXLogHook, readers []string, ctx *scard.Context) {
	lastestSerialNumberList := make([]string, len(readers))
	serialNumberMap := make(map[string]usafecard.USafeCard, len(readers))
	oldserialNumberReaderMap := s.getAllSerialNumberReaderMap()
	for i, reader := range readers {
		//通过轻量锁控制实现
		card := s.getReadyCard(edgeXLog, reader, ctx)

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
		if card == nil {
			edgeXLog.Warnf("get ready card fail,reader:%s", reader)
			s.putReadyCard(edgeXLog, reader, card)
			//return nil, errors.New("get no ready card")
			return
		}
		_, err := card.Status()
		if err != nil {
			//todo应当对外通知此reader存在异常
			edgeXLog.Warnf("reader:%s status err:%s", reader, err)
			//通过轻量锁控制实现
			s.putReadyCard(edgeXLog, reader, card)
			//原实现
			//closeCardConnection(card)
			continue
		}

		//读应用获取serial number
		var cmds = [][]byte{
			//选择应用
			{0x00, 0xA4, 0x04, 0x00, 0x0E, 0x49, 0x4F, 0x54, 0x5F, 0x41, 0x50, 0x50, 0x4C, 0x45, 0x54, 0x5F, 0x41, 0x49, 0x44},
			//真正获取sn指令
			{0x80, 0x02, 0x00, 0x00, 0x06, 0x41, 0x04, 0x00, 0x00, 0x00, 0x02},
		}
		for j, cmd := range cmds {
			edgeXLog.Infof("Transmit c-apdu: % x", cmd)
			rsp, err := card.Transmit(cmd)
			if err != nil {
				//todo应当对外通知此reader存在异常
				edgeXLog.Warnf("reader:%s Transmit apdu err:%s", reader, err)
				break
			}
			edgeXLog.Infof("Transmit r-apdu: %x", rsp)
			if j == 1 {
				lenRsp := len(rsp)
				//if rsp[lenRsp-1]==0x90&&rsp[lenRsp-2]==0x00 {
				if bytes.HasSuffix(rsp, []byte{0x90, 0x00}) {
					//更新SN与reader映射，存在并发问题
					//获取sn指令的响应结果为41tag+08长度+sn值+9000，应当截取sn值
					serialNumber := hex.EncodeToString(rsp[2 : lenRsp-2])
					serialNumber = strings.ToUpper(serialNumber)
					//读取前后值是否一致，不一致需要更新，一致则不需要
					//todo currCard.Reader == reader似乎可以去除，虽然设备插拔后reader可能变化，但设备插拔都会通过SerialNumberMap维护，没必要判断reader了
					if currCard, b := s.getSerialNumberMap(serialNumber); b && currCard.OperatingState == models.Up && currCard.Reader == reader {
						//serialNumberList[i] = ""
						//serialNumberList[i] = serialNumber
						lastestSerialNumberList[i] = serialNumber
					} else {
						//SerialNumberMap中获取不到的或者reader不一致的表示之前被拔除过
						//s.setSerialNumberMap(serialNumber, usafecard.USafeCard{Reader: reader, OperatingState: models.Up})
						serialNumberMap[serialNumber] = usafecard.USafeCard{Reader: reader, OperatingState: models.Up}
						lastestSerialNumberList[i] = serialNumber
					}
				}
			}
		}
		//通过轻量锁控制实现
		s.putReadyCard(edgeXLog, reader, card)
	}

	edgeXLog.Infof("the lastest devices list,%v", oldserialNumberReaderMap)
	//todo此时设备要是又拔了会有问题，但是多少有点离谱
	//管理可用设备
	res := make([]sdkModels.DiscoveredDevice, 0, 1)
	for serialNumber, usafeCardInfo := range serialNumberMap {
		if serialNumber != "" {
			if !s.sdk.DeviceExistsForName(serialNumber) {
				//从没存在过的设备，准备新增
				proto := make(map[string]models.ProtocolProperties)
				proto["pcsc"] = map[string]any{"SerialNumber": serialNumber}
				res = append(res, sdkModels.DiscoveredDevice{
					Name:        serialNumber,
					Protocols:   proto,
					Description: "found by discovery",
					Labels:      []string{"auto-discovery"}})
				s.setSerialNumberMap(serialNumber, usafeCardInfo)
			} else if _, ok := oldserialNumberReaderMap[serialNumber]; !ok {
				//cache中有，SerialNumberMap没有表示之前被移除过
				//之前被拔除的设备状态恢复到Up
				if err := s.sdk.UpdateDeviceOperatingState(serialNumber, models.Up); err != nil {
					edgeXLog.Warnf("update device:%s operating state to Up meet err:%s", serialNumber, err)
				} else {
					//cache.Dev
					//cache.Devices().RemoveByName(old)
					s.setSerialNumberMap(serialNumber, usafeCardInfo)
				}
			}
		}
	}
	//管理被拔除的设备——状态置为down
	//todo还需管理channel
	//timeNow := time.Now().String()
	s.deleteOldDevice(edgeXLog, oldserialNumberReaderMap, lastestSerialNumberList)
	//避免过于频繁的设备扫描,等待设备稳定,部分设备发现过程耗时较久
	//time.Sleep(time.Duration(s.serviceConfig.PcscCustom.Writable.DiscoverSleepDurationSecs) * time.Second)
	//PublishDeviceDiscoveryProgressSystemEvent用于发布设备发现进度的系统事件，50：表示当前设备发现的进度百分比，len(res)设备数量
	//s.sdk.PublishDeviceDiscoveryProgressSystemEvent(50, len(res), "")
	//将设备发现的停止标志设置为 false。这通常用于确保在设备发现过程结束后，设备发现功能可以继续正常工作
	defer s.setStopDeviceDiscovery(false)
	if len(res) > 0 {
		s.deviceCh <- res
	}
	//s.deleteOldDevice(oldserialNumberReaderMap, serialNumberList)

}
func (s *PcscDriver) setSerialNumberMap(key string, value usafecard.USafeCard) {
	s.snWLock.Lock()
	s.serialNumberReaderMap[key] = value
	s.snWLock.Unlock()
}
func (s *PcscDriver) removeSerialNumberMap(key string) {
	s.snWLock.Lock()
	delete(s.serialNumberReaderMap, key)
	s.snWLock.Unlock()
}
func (s *PcscDriver) getSerialNumberMap(key string) (usafecard.USafeCard, bool) {
	s.snWLock.RLock()
	reader, ok := s.serialNumberReaderMap[key]
	s.snWLock.RUnlock()
	return reader, ok
}

func (s *PcscDriver) getAllSerialNumberReaderMap() map[string]usafecard.USafeCard {
	s.snWLock.RLock()
	all := make(map[string]usafecard.USafeCard, len(s.serialNumberReaderMap))
	for k, v := range s.serialNumberReaderMap {
		all[k] = v
	}
	s.snWLock.RUnlock()
	return all
}

func (s *PcscDriver) getReadyCard(edgeXLog *log.EdgeXLogHook, reader string, ctx *scard.Context) *scard.Card {
	channel := s.readerCh[reader]
	var card *scard.Card
	var err error
	edgeXLog.Debugf("等待ReadyCard,reader:%s", reader)
	//todo需要考虑是否可能存在一直挂起的情况
	<-channel
	edgeXLog.Debugf("成功获取ReadyCard,reader:%s", reader)
	if ctx == nil {
		ctx, err = scard.EstablishContext()
		if err != nil {
			edgeXLog.Warnf("Pcsc Resource Manager is nil.And hard to recover by getting pcsc ResourceManager,err:%s", err)
			return nil
		}
		edgeXLog.Warnf("Pcsc Resource Manager lost.Recover during getting ready card.Need to reseach.")
	}
	if ctx != nil {
		//scard.ShareExclusive在各类读卡器上兼容性强，确保独占，同时只可一个应用连接卡片
		//scard.ShareShared多应用共享访问，可实现实时监听状态变化
		//scard.ShareDirect直接访问或实时控制底层协议，需提前验证设备兼容性
		//scard.ProtocolT0每次传输1字节，通信开销大，早期设备采用此方式，兼容性强
		//scard.ProtocolT1基于块的异步传输，效率高，需设备支持块传输
		//scard.ProtocolAny自动检测由智能卡接口自动协商
		//card, err = ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
		card, err = ctx.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
		if err != nil {
			//todo应当对外通知此reader存在异常
			edgeXLog.Warnf("connect with reader:%s,err:%s", reader, err)
			//原实现
			//closeCardConnection(card)
		}
		return card
	}
	return nil

}

func (s *PcscDriver) putReadyCard(edgeXLog *log.EdgeXLogHook, reader string, card *scard.Card) {
	channel := s.readerCh[reader]
	//todo需考虑当前通过readerCh管理reader的方式是否还可能出现card为nil的情况，如果为nil应该如何处理？是否应该通过readerCh释放reader？
	s.closeCardConnection(edgeXLog, card)
	edgeXLog.Debugf("card连接关闭,准备释放ReadyCard,reader:%s", reader)
	channel <- struct{}{}
	edgeXLog.Debugf("释放ReadyCard成功,reader:%s", reader)
}

func (s *PcscDriver) closeCardConnection(edgeXLog *log.EdgeXLogHook, card *scard.Card) {
	if card != nil {
		//连续操作场景：选择 LeaveCard，避免重复连接开销。
		//状态重置需求：选择 ResetCard，用于初始化或恢复卡片状态。
		//临时暂停场景：选择 UnpowerCard，在不弹出卡片的情况下断电保护。
		//操作结束场景：选择 EjectCard，确保卡片安全移除，适合用户交互流程。
		err := card.Disconnect(scard.ResetCard)
		if err != nil {
			edgeXLog.Warnf("release card connetion meet err,%v", err)
		}
	} else {
		edgeXLog.Warnf("card is nil during close card connetion")
	}
}

func ContainElement[T comparable](slice []T, element T) bool {
	for _, s := range slice {
		if s == element {
			return true
		}
	}
	return false
}

func (s *PcscDriver) deleteOldDevice(edgeXLog *log.EdgeXLogHook, oldserialNumberReaderMap map[string]usafecard.USafeCard, lastestSerialNumberList []string) {
	//管理被拔除的设备——状态置为down
	//todo还需管理channel
	//timeNow := time.Now().String()
	for old, _ := range oldserialNumberReaderMap {
		if !ContainElement[string](lastestSerialNumberList, old) {
			//proto := make(map[string]models.ProtocolProperties)
			//proto["pcsc"] = map[string]any{"SerialNumber": old}
			//res = append(res, sdkModels.DiscoveredDevice{
			//	Name:        old,
			//	Protocols:   proto,
			//	Description: "removed by discovery",
			//	Labels:      []string{"auto-discovery", "removed", timeNow}})
			//s.sdk.
			//s.sdk.cache.Devices

			//if err := s.sdk.RemoveDeviceByName(old); err != nil {
			//放弃发送拔除设备通知，转为采用更新设备状态的方式
			if err := s.sdk.UpdateDeviceOperatingState(old, models.Down); err != nil {
				edgeXLog.Warnf("update device:%s operating state meet err:%s", old, err)
			} else {
				//cache.Devices().RemoveByName(old)
				s.removeSerialNumberMap(old)
			}
		}
	}
}
