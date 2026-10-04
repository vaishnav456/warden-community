package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const supportMaxFrame = 65536

type helpdeskField struct {
	ID       string             `json:"id"`
	Label    string             `json:"label"`
	Type     string             `json:"type"`
	Required bool               `json:"required"`
	Options  []string           `json:"options"`
	ShowIf   *helpdeskCondition `json:"show_if,omitempty"`
}
type helpdeskRule struct {
	Source   string `json:"source"`
	Field    string `json:"field,omitempty"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}
type helpdeskCondition struct {
	Mode  string         `json:"mode"`
	Rules []helpdeskRule `json:"rules"`
}

func helpdeskFieldVisible(field helpdeskField, answers, context map[string]string) bool {
	if field.ShowIf == nil {
		return true
	}
	all, any := true, false
	for _, rule := range field.ShowIf.Rules {
		actual := context[rule.Source]
		if rule.Source == "field" {
			actual = answers[rule.Field]
		}
		matches := actual == rule.Value
		if rule.Operator == "not_equals" {
			matches = !matches
		}
		all = all && matches
		any = any || matches
	}
	if field.ShowIf.Mode == "any" {
		return any
	}
	return all
}

type helpdeskForm struct {
	Categories []string        `json:"categories"`
	Fields     []helpdeskField `json:"fields"`
}
type helpdeskTicket struct {
	ID       string  `json:"request_id"`
	Number   string  `json:"number"`
	Subject  string  `json:"subject"`
	Status   string  `json:"status"`
	Priority string  `json:"priority"`
	Mode     string  `json:"service_mode"`
	Visit    *string `json:"visit_at"`
}
type helpdeskEntry struct {
	Author  string `json:"author"`
	Message string `json:"message"`
	Created string `json:"created_at"`
}
type helpdeskData struct {
	Form          helpdeskForm      `json:"form"`
	Tickets       []helpdeskTicket  `json:"tickets"`
	Thread        []helpdeskEntry   `json:"thread"`
	Description   string            `json:"description"`
	HasMore       bool              `json:"has_more"`
	Status        string            `json:"status"`
	LatestReplyID string            `json:"latest_reply_id"`
	Context       map[string]string `json:"context"`
}

func newSupportID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	raw[6] = (raw[6] & 15) | 64
	raw[8] = (raw[8] & 63) | 128
	h := hex.EncodeToString(raw[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
func readSupportFrame(r io.Reader) ([]byte, error) {
	header, err := readExact(r, 4)
	if err != nil {
		return nil, err
	}
	size := binary.LittleEndian.Uint32(header)
	if size == 0 || size > supportMaxFrame {
		return nil, errors.New("invalid helpdesk frame")
	}
	return readExact(r, int(size))
}
func writeSupportFrame(w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > supportMaxFrame {
		return errors.New("helpdesk response exceeds frame limit")
	}
	frame := make([]byte, 4+len(raw))
	binary.LittleEndian.PutUint32(frame, uint32(len(raw)))
	copy(frame[4:], raw)
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}
func supportActionValid(request supportRequest) bool {
	switch request.Action {
	case "module-launch":
		return true
	case "status", "activity", "form", "list":
		return true
	case "detail", "reopen":
		return len(request.RequestID) == 36 && request.Page >= 0 && request.Page <= 10000
	case "reply":
		return len(request.RequestID) == 36 && len(request.MessageID) == 36 && validateSupportMessage(request.Message) == nil
	case "", "create":
		return validateSupportMessage(request.Message) == nil
	}
	return false
}
func supportReadOnly(action string) bool {
	return action == "status" || action == "activity" || action == "form" || action == "list" || action == "detail"
}
func supportServerRequest(request supportRequest, username string) supportResponse {
	route := "/api/agent/support-request"
	switch request.Action {
	case "form":
		route = "/api/agent/support-form"
	case "status", "list", "detail":
		route = "/api/agent/support-status"
	case "reply":
		route = "/api/agent/support-reply"
	case "reopen":
		route = "/api/agent/support-reopen"
	}
	body := map[string]interface{}{"username": username, "message": request.Message, "subject": request.Subject,
		"category": request.Category, "priority": request.Priority, "fields": request.Fields, "page": request.Page}
	if request.RequestID != "" {
		body["request_id"] = request.RequestID
	}
	if request.MessageID != "" {
		body["message_id"] = request.MessageID
	}
	result, err := apiPost(route, body, true, 10)
	if err != nil || result["ok"] != true {
		return supportResponse{Message: "The server did not confirm this action. Check connectivity or whether the ticket was resolved, then retry."}
	}
	response := supportResponse{OK: true, Message: "Your ticket is in the helpdesk queue. No remote access has been granted."}
	switch request.Action {
	case "status":
		response.Message = fmt.Sprintf("Request: %v\nSupport arrangement: %v", result["status"], result["service_mode"])
		if result["status"] == "none" {
			response.Message = "No previous ticket for your Windows account."
		}
		if replies, ok := result["replies"].([]interface{}); ok {
			for _, r := range replies {
				if text, ok := r.(string); ok {
					response.Message += "\nHelpdesk: " + text
				}
			}
		}
	case "reply":
		response.Message = "Your reply was received by the helpdesk."
	case "reopen":
		response.Message = "Your ticket was reopened."
	default:
		raw, _ := json.Marshal(result)
		var data helpdeskData
		if json.Unmarshal(raw, &data) != nil {
			return supportResponse{Message: "Invalid helpdesk response."}
		}
		response.Data = &data
		if id, ok := result["request_id"].(string); ok {
			response.RequestID = id
		}
	}
	return response
}
