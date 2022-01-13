package dtcsp

/*
#cgo linux LDFLAGS: -ldasdf -ldtcsp -ldtrtl -lpthread -ldl
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <math.h>
#include "dtcspapi.h"

int rv = 0;
void *pContext;

// 1.初始化DTCSP接口库
int DTCSPInit(DTCSP_VOID_PTR pContext, DTCSP_CHAR_PTR pConfigureFileName,DTCSP_UCHAR_PTR pPassWD)
{
	rv = DTCSP_Init(&pContext, pConfigureFileName, pPassWD);
	if(rv != DTCSP_SUCCESS)
	{
		printf("Init DTCSP API error\n");
	}
	return rv;
}

// 2. 关闭DTCSP接口库，释放相关资源
int DTCSPEnd(DTCSP_VOID_PTR pContext)
{	
	rv = DTCSP_End(&pContext);
	if(rv != DTCSP_SUCCESS)
	{
		printf("End DTCSP error\n");
		return rv;
	}
	return rv;
}

// 3. 获取当前DTCSP库的版本号
int DTCSPGetDTCSPVersion(DTCSP_UCHAR_PTR pVersion)
{
	rv = DTCSP_GetDTCSPVersion(pVersion);
	if(rv != DTCSP_SUCCESS){
		printf("Get DTCSP version error\n");
	}
	printf("DTCSP Version is %s\n",pVersion);
	return rv;
}
 */
import "C"
import (
	sdf_go "github.com/Ruadgedy/sdf-go"
	"unsafe"
)

var cspContext C.DTCSP_VOID_PTR
var stubData = []byte{0}

func CMessage1(data []byte) C.DTCSP_UCHAR_PTR {
	l := len(data)
	if l == 0 {
		data = stubData
	}
	dataPtr := C.DTCSP_UCHAR_PTR(unsafe.Pointer(&data[0]))
	return dataPtr
}

type Csp struct {
}

// 1. 初始化DTCSP库
func (c *Csp) DTCSPInit() (C.DTCSP_VOID_PTR,error) {
	var err C.int
	var passwd C.DTCSP_UCHAR_PTR
	err = C.DTCSPInit(&cspContext, CMessage1([]byte("dtcrypt.ini")),passwd)
	err1 := sdf_go.ToError(err)
	return cspContext, err1
}

// 2. 关闭DTCSP库
func (c *Csp) DTCSPEnd(ctx C.DTCSP_VOID_PTR) error {
	err1 := C.DTCSPEnd(&ctx)
	err := sdf_go.ToError(err1)
	return err
}

// 3. 获取当前DTCSP库的版本号
func (c *Csp) DTCSPGetDTCSPVersion() (string,error) {
	version := make([]byte,0,50)
	ptr := CMessage1(version)
	err1 := C.DTCSPGetDTCSPVersion(ptr)
	err := sdf_go.ToError(err1)
	ret := ConvertUcharPtrToString(ptr)
	return ret,err
}