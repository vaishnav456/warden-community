package main

import ("crypto/rand";"encoding/binary";"encoding/hex";"errors";"io")

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
