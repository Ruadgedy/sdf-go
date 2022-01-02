package sdf_go

import (
	"fmt"
	"os"
)

var Cx = Ctx{}
var deviceHandle DeviceHandleType
var sessionHandle SessionHandleType
var err error

// init initializes the device handle
func init()  {
	deviceHandle,err = Cx.SDFOpenDevice()
	if err != nil {
		fmt.Println("Open SDF device failed: ", err)
		os.Exit(1)
	}

}