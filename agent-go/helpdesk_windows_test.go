package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestHelpdeskFramesAreBoundedAndIndependentOfIdentityBroker(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 12000)
	var frame bytes.Buffer
	if err := writeSupportFrame(&frame, raw); err != nil {
		t.Fatal(err)
	}
	decoded, err := readSupportFrame(&frame)
	if err != nil || !bytes.Equal(raw, decoded) {
		t.Fatal("ticket frame round trip", err)
	}
	for _, size := range []uint32{0, supportMaxFrame + 1} {
		var invalid bytes.Buffer
		binary.Write(&invalid, binary.LittleEndian, size)
		if _, err := readSupportFrame(&invalid); err == nil {
			t.Fatal("unbounded frame accepted")
		}
	}
	if err := writeSupportFrame(&frame, bytes.Repeat([]byte("x"), supportMaxFrame+1)); err == nil {
		t.Fatal("oversize response accepted")
	}
}
func TestHelpdeskActionsCannotDispatchPrivilegedOperations(t *testing.T) {
	for _, action := range []string{"remote", "execute", "quit", "approve", "delete", "arbitrary"} {
		if supportActionValid(supportRequest{Action: action, Message: "hello"}) {
			t.Fatal("unexpected local operation", action)
		}
	}
	id := newSupportID()
	if len(id) != 36 || id == newSupportID() {
		t.Fatal("unstable or nonunique identifier")
	}
	if !supportActionValid(supportRequest{Action: "reply", RequestID: id, MessageID: newSupportID(), Message: "hello"}) {
		t.Fatal("valid reply rejected")
	}
	if supportActionValid(supportRequest{Action: "reply", RequestID: id, Message: "hello"}) {
		t.Fatal("non-idempotent reply accepted")
	}
	if supportActionValid(supportRequest{Action: "detail", RequestID: id, Page: -1}) {
		t.Fatal("invalid page accepted")
	}
}

func TestHelpdeskConditionalVisibilityMatchesServerRules(t *testing.T) {
	field := helpdeskField{ShowIf: &helpdeskCondition{Mode: "all", Rules: []helpdeskRule{
		{Source: "field", Field: "location", Operator: "equals", Value: "Home"},
		{Source: "branch", Operator: "equals", Value: "branch-a"},
	}}}
	if !helpdeskFieldVisible(field, map[string]string{"location": "Home"}, map[string]string{"branch": "branch-a"}) {
		t.Fatal("matching field hidden")
	}
	if helpdeskFieldVisible(field, map[string]string{"location": "Office"}, map[string]string{"branch": "branch-a"}) {
		t.Fatal("nonmatching field shown")
	}
	field.ShowIf.Mode = "any"
	if !helpdeskFieldVisible(field, map[string]string{"location": "Office"}, map[string]string{"branch": "branch-a"}) {
		t.Fatal("any condition failed")
	}
	field.ShowIf.Rules = []helpdeskRule{{Source: "priority", Operator: "not_equals", Value: "urgent"}}
	if helpdeskFieldVisible(field, nil, map[string]string{"priority": "urgent"}) {
		t.Fatal("else rule failed")
	}
}
