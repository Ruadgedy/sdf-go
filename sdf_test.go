package sdf_go

import (
	"os"
	"testing"
)

var ctx Ctx

var deviceHandle DeviceHandleType
var sessionHandle SessionHandleType

func TestSDFOpenDevice(t *testing.T) {
	dH, err := ctx.SDFOpenDevice()
	if err != nil {
		t.Fatalf("打开设备出错: %s",err.Error())
	}
	t.Log("打开设备成功")

	deviceHandle = dH

	err =ctx.SDFCloseDevice(dH)
	if err != nil {
		t.Fatalf("关闭设备出错:%s",err.Error())
	}

	t.Log("关闭设备成功")

	t.Log("Device Handle has been init")
}

func TestSDFCloseDevice(t *testing.T) {
	deviceHandleType, err := ctx.SDFOpenDevice()
	if err != nil {
		t.Fatalf("打开设备出错: %s",err.Error())
	}
	t.Log("打开设备成功")

	err = ctx.SDFCloseDevice(deviceHandleType)
	if err != nil {
		t.Fatalf("关闭设备出错:%s",err.Error())
	}

	t.Log("关闭设备成功")
}

func TestSDFOpenSession(t *testing.T) {
	deviceHandleType, err := ctx.SDFOpenDevice()
	if err != nil {
		t.Fatalf("打开设备出错：%s\n",err.Error())
	}

	t.Log("Open device ok\n")

	sessionHandleType, err := ctx.SDFOpenSession(deviceHandleType)
	if err != nil {
		t.Fatalf("Open session failed:%s",err.Error())
	}
	t.Log("Open session success")
	sessionHandle = sessionHandleType
}

func TestSDFCloseSession(t *testing.T) {
	deviceHandleType, err := ctx.SDFOpenDevice()
	if err != nil {
		t.Fatalf("打开设备出错：%s\n",err.Error())
	}

	t.Log("Open device ok\n")

	sessionHandleType, err := ctx.SDFOpenSession(deviceHandleType)
	if err != nil {
		t.Fatalf("Open session failed:%s",err.Error())
	}
	t.Log("Open session success")

	err = ctx.SDFCloseSession(sessionHandleType)
	if err != nil {
		t.Fatalf("Close session failed:%s",err.Error())
	}
	t.Log("Close session success")
}

// 将初始化Device和Session的操作交给下面的函数
func TestMain(m *testing.M)  {
	device, _ := ctx.SDFOpenDevice()
	deviceHandle = device
	session, _ := ctx.SDFOpenSession(device)
	sessionHandle = session

	os.Exit(m.Run())
}

func TestSDFGetDeviceInfo(t *testing.T)  {

	deviceInfo, err := ctx.SDFGetDeviceInfo(sessionHandle)
	if err != nil {
		t.Fatalf("Get device info error:%s\n",err.Error())
	}
	t.Log(deviceInfo)
}

func TestSDFGenerateRandom(t *testing.T) {
	bytes, err := ctx.SDFGenerateRandom(sessionHandle, 32)
	if err != nil {
		t.Fatalf("generate random error :%s\n",err.Error())
	}
	t.Log(string(bytes))
}

func TestGenerateKeyPair_RSA(t *testing.T)  {
	pubKey, privateKey, err := ctx.SDFGenerateKeyPair_RSA(sessionHandle, 1024)
	if err != nil {
		t.Fatalf("Generate key pair error:%s\n",err.Error())
	}
	t.Log(pubKey)
	t.Log(privateKey)
}

func TestGenerateKeyPair_ECC(t *testing.T) {
	pubKey, privateKey, err := ctx.SDFGenerateKeyPair_ECC(sessionHandle, SGD_SM2_3, 256)
	if err != nil {
		t.Fatalf("Generate ECC key pair error:%s\n",err.Error())
	}
	t.Log(pubKey)
	t.Log(privateKey)
}