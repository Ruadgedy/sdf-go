package sdf_go

import (
	"fmt"
	"os"
)

var Cx = Ctx{}
var GlobalDevice DeviceHandleType
var GlobalSession SessionHandleTyep
var err error

// init initializes the device handle
func init()  {
	GlobalDevice,err = Cx.SDFOpenDevice()
	if err != nil {
		fmt.Println("Open SDF device failed: ", err)
		os.Exit(1)
	}
	
	GlobalSession,err = Cx.SDFOpenSession(GlobalDevice)
	if err != nil {
		fmt.Println("Open SDF session failed:", err)
		os.Exit(1)
	}
		
}
