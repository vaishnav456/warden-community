//go:build !warden_core

package main

import (
	"testing"
	"unsafe"
)

func TestTicketFormRequiredAndConditionalAnswers(t *testing.T) {
	if normalizeTicketInput(" first\r\nsecond ") != "first\nsecond" {
		t.Fatal("Windows multiline text not normalized")
	}
	def := helpdeskForm{Categories: []string{"Hardware", "Software"}, Fields: []helpdeskField{
		{ID: "location", Label: "Location", Required: true, ShowIf: &helpdeskCondition{Mode: "all", Rules: []helpdeskRule{{Source: "category", Value: "Hardware"}}}},
	}}
	r := supportRequest{Subject: "Printer unavailable", Message: "Cannot print this morning", Fields: map[string]string{}}
	context := map[string]string{"category": "Software"}
	if _, err := validateTicketForm(r, def, context); err != "" {
		t.Fatal(err)
	}
	context["category"] = "Hardware"
	if id, _ := validateTicketForm(r, def, context); id != "location" {
		t.Fatal("visible required field not checked")
	}
	r.Fields["location"] = "Reception"
	if _, err := validateTicketForm(r, def, context); err != "" {
		t.Fatal(err)
	}
	r.Subject = ""
	if id, _ := validateTicketForm(r, def, context); id != "subject" {
		t.Fatal("missing subject accepted")
	}
}

func TestNativeTicketFormControlsAndHiddenAnswers(t *testing.T) {
	parent, _, _ := uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString("STATIC"))), 0, 0x80000000, 0, 0, 600, 600, 0, 0, 0, 0)
	if parent == 0 {
		t.Fatal("cannot create hidden native parent")
	}
	defer uiDestroyWindow.Call(parent)
	font, _, _ := gdi32DLL.NewProc("GetStockObject").Call(17)
	u := &wardenUI{window: parent, width: 600, height: 600, scale: 1, font: font}
	r := supportRequest{Subject: "Printer", Message: "Cannot print", Priority: "normal", Fields: map[string]string{"location": "Reception"}}
	f := &ticketFormUI{request: &r, context: map[string]string{}, definition: helpdeskForm{Categories: []string{"Hardware", "Software"}, Fields: []helpdeskField{{ID: "location", Label: "Location", Required: true, ShowIf: &helpdeskCondition{Mode: "all", Rules: []helpdeskRule{{Source: "category", Value: "Hardware"}}}}}}}
	currentTicketForm = f
	defer func() { currentTicketForm = nil }()
	if !f.create(u, 0) {
		t.Fatal("cannot create form")
	}
	defer f.close()
	if len(f.controls) != 5 || !f.controls[4].visible {
		t.Fatal("required native controls missing")
	}
	f.scrollTo(100000)
	if f.offset != f.total-f.page {
		t.Fatal("scroll unbounded")
	}
	uiSendMessage.Call(f.controls[1].input, 0x14e, 1, 0)
	f.layout()
	answers, _ := f.answers()
	if f.controls[4].visible || answers["location"] != "" {
		t.Fatal("hidden answer retained in submitted payload")
	}
	uiSendMessage.Call(f.controls[1].input, 0x14e, 0, 0)
	f.layout()
	if f.value(f.controls[4]) != "Reception" {
		t.Fatal("changing selection erased user's input")
	}
}
