package Common

import "testing"

func TestRe(t *testing.T) {
	result1 := GetDNSLog_Platform_Golang("https://dig.pm")
	CheckDNSLog_Platform_Golang("https://dig.pm", result1)
}
