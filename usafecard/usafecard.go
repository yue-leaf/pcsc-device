package usafecard

import "github.com/edgexfoundry/go-mod-core-contracts/v4/models"

type USafeCard struct {
	Reader         string
	OperatingState models.OperatingState
}
