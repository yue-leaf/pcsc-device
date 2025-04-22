package client

import (
	"fmt"
	"github.com/ebfe/scard"
)

var client *scard.Context

func init() {
	ctx, err := scard.EstablishContext()
	if err != nil {
		fmt.Println("初始化PcscClient失败")
		return
	}
	client = ctx
}
func GetClient() *scard.Context {
	return client
}
func CloseClient() error {
	if err := client.Release(); err != nil {
		return err
	}
	return nil
}
