package main

import (
 "io"
 "golang.org/x/sys/windows"
)

var user32DLL = windows.NewLazySystemDLL("user32.dll")
var kernel32DLL = windows.NewLazySystemDLL("kernel32.dll")
var gdi32DLL = windows.NewLazySystemDLL("gdi32.dll")
var procSelectObject = gdi32DLL.NewProc("SelectObject")
var procDeleteObject = gdi32DLL.NewProc("DeleteObject")
var procSetProcessDPIAware = user32DLL.NewProc("SetProcessDPIAware")
type workspacePoint struct{ X,Y int32 }
type workspaceMouseTrack struct { Size,Flags uint32; Window uintptr; HoverTime uint32 }
type workspaceDrawItem struct { ControlType,ControlID,ItemID,Action,State uint32; Window,DC uintptr; Rect uiRect; Data uintptr }
type workspaceActivity struct { RemoteActive bool `json:"remote_active"`; RecordingActive bool `json:"recording_active"`; RecordingSupported bool `json:"recording_supported"` }
type pipeFile struct { h windows.Handle }
func (p pipeFile) Read(buf []byte) (int,error) { var n uint32; err:=windows.ReadFile(p.h,buf,&n,nil); if err==nil && n==0 {err=io.EOF};return int(n),err }
func (p pipeFile) Write(buf []byte) (int,error) { var n uint32;err:=windows.WriteFile(p.h,buf,&n,nil);return int(n),err }
func readExact(r io.Reader,n int)([]byte,error) {buf:=make([]byte,n);_,err:=io.ReadFull(r,buf);return buf,err}
