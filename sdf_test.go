package sdf_go

import (
	"crypto/rand"
	"golang.org/x/text/encoding/simplifiedchinese"
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

func ConvertUTF8ToGBK(str string) string {
	ret, err := simplifiedchinese.GBK.NewEncoder().String(str)
	if err != nil {
		return ""
	}
	return ret
}

func ConvertGBKToUTF8(str string) string {
	ret, _ := simplifiedchinese.GBK.NewDecoder().String(str)
	return ret
}
func TestSDFGetDeviceInfo(t *testing.T)  {

	deviceInfo, err := ctx.SDFGetDeviceInfo(sessionHandle)
	if err != nil {
		t.Fatalf("Get device info error:%s\n",err.Error())
	}
	t.Log("IssuerName: " + ConvertGBKToUTF8(deviceInfo.IssuerName))
	t.Log("DeviceName: " + ConvertGBKToUTF8(deviceInfo.DeviceName))
	t.Log("DeviceSerial: " + deviceInfo.DeviceSerial)
	t.Logf("DeviceVersion: %d", deviceInfo.DeviceVersion)
}

func TestSDFGenerateRandom(t *testing.T) {
	bytes, err := ctx.SDFGenerateRandom(sessionHandle, 32)
	if err != nil {
		t.Fatalf("generate random error :%s\n",err.Error())
	}
	t.Log(bytes)
}

func TestGenerateKeyPair_RSA(t *testing.T)  {
	pubKey, privateKey, err := ctx.SDFGenerateKeyPair_RSA(sessionHandle, 1024)
	if err != nil {
		t.Fatalf("Generate key pair error:%s\n",err.Error())
	}
	t.Log("publicKey:")
	t.Logf("Bits:%d", pubKey.Bits)
	t.Log("Pub M:" + pubKey.M)
	t.Log("Pub E:" + pubKey.E)
	t.Log(privateKey)
}

func TestGenerateKeyPair_ECC(t *testing.T) {
	// 生成椭圆曲线加密算法
	pubKey, priv, err := ctx.SDFGenerateKeyPair_ECC(sessionHandle, SGD_SM2_3, 256)
	if err != nil {
		t.Fatalf("Generate ECC key pair error:%s\n",err.Error())
	}
	t.Log("pubKey:")
	t.Logf("Bits: %d", pubKey.Bits)
	t.Logf("X: %v", []byte(pubKey.X))
	t.Logf("Y: %v", []byte(pubKey.Y))

	t.Log("privateKey:")
	t.Logf("Bits: %d", priv.Bits)
	t.Logf("D: %v", []byte(priv.K))
}

func TestHash(t *testing.T) {
	size := 1024
	origin := make([]byte, size)
	rand.Read(origin)

	_, _, err := ctx.SDFGenerateKeyPair_ECC(sessionHandle, SGD_SM2_1, 256)
	DoErr(t,err)

	_, err = ctx.SDFHashInit(sessionHandle, SGD_SM3, nil, 0)
	DoErr(t,err)

	err = ctx.SDFHashUpdate(sessionHandle, origin, uint(size))
	DoErr(t,err)

	sum, sumLength, err := ctx.SDFHashFinal(sessionHandle)
	DoErr(t,err)
	t.Logf("Sum: %v\n",sum)
	t.Logf("Sum length: %d\n",sumLength)
}

func DoErr(t *testing.T, err error) {
	if err != nil {
		t.Fatal(err)
	}
}