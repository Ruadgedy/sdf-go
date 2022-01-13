package dtcsp

import "testing"

var csp Csp

func TestMain(m *testing.M)  {

}

func TestDTCSPInit(t *testing.T) {
	ctx, err := csp.DTCSPInit()
	if err != nil {
		t.Fatal("Init DTCSP error:", err.Error())
	}
	t.Logf("DTCSP Init success: %v",ctx)
}
