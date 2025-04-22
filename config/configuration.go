//
// Copyright (c) 2023 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package config

import (
	"errors"
)

// This file contains example of custom configuration that can be loaded from the service's configuration.yaml
// and/or the Configuration Provider, aka Consul (if enabled).
// For more details see https://docs.edgexfoundry.org/2.0/microservices/device/Ch-DeviceServices/#custom-configuration

// Example structured custom configuration types. Must be wrapped with an outer struct with
// single element that matches the top level custom configuration element in your configuration.yaml file,
// 'SimpleCustom' in this example.
type ServiceConfig struct {
	PcscCustom PcscCustomConfig
}

// SimpleCustomConfig is example of service's custom structured configuration that is specified in the service's
// configuration.yaml file and Configuration Provider (aka Consul), if enabled.
type PcscCustomConfig struct {
	Writable PcscWritable
}

// SimpleWritable defines the service's custom configuration writable section, i.e. can be updated from Consul
type PcscWritable struct {
	DiscoverSleepDurationSecs int64
}

// UpdateFromRaw updates the service's full configuration from raw data received from
// the Service Provider.
func (sw *ServiceConfig) UpdateFromRaw(rawConfig interface{}) bool {
	configuration, ok := rawConfig.(*ServiceConfig)
	if !ok {
		return false //errors.New("unable to cast raw config to type 'ServiceConfig'")
	}

	*sw = *configuration

	return true
}

// Validate ensures your custom configuration has proper values.
// Example of validating the sample custom configuration
func (pcc *PcscCustomConfig) Validate() error {
	if pcc.Writable.DiscoverSleepDurationSecs <= 0 {
		return errors.New("PcscCustom.Writable.DiscoverSleepDurationSecs configuration setting must be greater than 0")
	}

	return nil
}
