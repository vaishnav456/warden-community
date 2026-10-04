package main

// A single native form: no browser engine, credentials or elevated UI process.
import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var currentTicketForm *ticketFormUI
var ticketPanelCallback = windows.NewCallback(ticketPanelProc)

type ticketControl struct {
	label, input uintptr
	original     uintptr
	name         string
	options      []string
	height, top  int32
	visible      bool
}
type ticketFormUI struct {
	u                   *wardenUI
	panel, original     uintptr
	definition          helpdeskForm
	context             map[string]string
	controls            []ticketControl
	request             *supportRequest
	offset, total, page int32
	updating            bool
	inputBrush          uintptr
}
type ticketScrollInfo struct {
	Size, Mask      uint32
	Min, Max        int32
	Page            uint32
	Position, Track int32
}

func runTicketForm(def helpdeskForm, context map[string]string, request *supportRequest) bool {
	f := &ticketFormUI{definition: def, context: context, request: request}
	currentTicketForm = f
	defer func() { currentTicketForm = nil }()
	defer f.close()
	return runWardenUserDialog("Warden Support", "New support ticket", "",
		"Tell IT what is wrong. Your Windows account is attached automatically. Never include passwords or recovery keys.", "info", true) == 0
}

func (f *ticketFormUI) create(u *wardenUI, instance uintptr) bool {
	f.u = u
	u.ticket = f
	f.inputBrush, _, _ = uiCreateBrush.Call(0x00362b17)
	f.page = u.height - u.px(280)
	f.panel, _, _ = uiCreateWindow.Call(0x00010000, uintptr(unsafe.Pointer(uiString("STATIC"))), 0,
		0x50000000|0x02000000, uintptr(u.px(32)), uintptr(u.px(150)), uintptr(u.width-u.px(76)), uintptr(f.page), u.window, 40, instance, 0)
	if f.panel == 0 {
		return false
	}
	f.original, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(f.panel, ^uintptr(3), ticketPanelCallback)
	if f.original == 0 {
		return false
	}
	add := func(name, label, value string, options []string, multiline bool, limit uintptr) bool {
		c := ticketControl{name: name, options: options, height: u.px(42), visible: true}
		c.label, _, _ = uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString("STATIC"))), uintptr(unsafe.Pointer(uiString(label))), 0x50000080, 0, 0, 0, 0, f.panel, 0, instance, 0)
		class, style := "EDIT", uintptr(0x00010000|0x0080)
		if multiline {
			style = 0x00010000 | 0x0004 | 0x0040 | 0x1000
			c.height = u.px(130)
		}
		if len(options) > 0 {
			class = "COMBOBOX"
			style = 0x00010003 | 0x00200000 | 0x10 | 0x200 // native owner-drawn dropdown, retains keyboard/accessibility
		}
		c.input, _, _ = uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString(class))), uintptr(unsafe.Pointer(uiString(value))), 0x50000000|style, 0, 0, 0, 0, f.panel, uintptr(100+len(f.controls)), instance, 0)
		if c.label == 0 || c.input == 0 {
			return false
		}
		uiSendMessage.Call(c.label, 0x30, u.smallFont, 1)
		uiSendMessage.Call(c.input, 0x30, u.font, 1)
		if len(options) > 0 {
			uiSendMessage.Call(c.input, 0x153, ^uintptr(0), uintptr(u.px(36)))
			uiSendMessage.Call(c.input, 0x153, 0, uintptr(u.px(32)))
			selection := 0
			for i, option := range options {
				uiSendMessage.Call(c.input, 0x143, 0, uintptr(unsafe.Pointer(uiString(option))))
				if value == option {
					selection = i
				}
			}
			uiSendMessage.Call(c.input, 0x14e, uintptr(selection), 0)
		} else {
			uiSendMessage.Call(c.input, 0xc5, limit, 0)
		}
		f.controls = append(f.controls, c)
		original, _, _ := user32DLL.NewProc("SetWindowLongPtrW").Call(c.input, ^uintptr(3), ticketInputCallback)
		f.controls[len(f.controls)-1].original = original
		if original == 0 {
			return false
		}
		return true
	}
	if !add("subject", "Subject *", f.request.Subject, nil, false, 160) ||
		!add("category", "Category *", f.request.Category, f.definition.Categories, false, 0) ||
		!add("priority", "Priority *", f.request.Priority, []string{"normal", "low", "high", "urgent"}, false, 0) ||
		!add("description", "Description * — what happened?", f.request.Message, nil, true, 2000) {
		return false
	}
	for _, field := range f.definition.Fields {
		label := field.Label
		if field.Required {
			label += " *"
		} else {
			label += " (optional)"
		}
		options := []string(nil)
		if field.Type == "select" {
			options = append([]string{"Choose an option…"}, field.Options...)
		}
		if !add(field.ID, label, f.request.Fields[field.ID], options, false, 500) {
			return false
		}
	}
	u.scroll, _, _ = uiCreateWindow.Call(0, uintptr(unsafe.Pointer(uiString("BUTTON"))), uintptr(unsafe.Pointer(uiString("Scroll ticket form"))), 0x5001000b,
		uintptr(u.width-u.px(40)), uintptr(u.px(150)), uintptr(u.px(14)), uintptr(f.page), u.window, 21, instance, 0)
	if u.scroll == 0 {
		return false
	}
	u.scrollOriginal, _, _ = user32DLL.NewProc("SetWindowLongPtrW").Call(u.scroll, ^uintptr(3), uiScrollCallback)
	if u.scrollOriginal == 0 {
		return false
	}
	f.layout()
	return true
}
func (f *ticketFormUI) value(c ticketControl) string {
	if len(c.options) > 0 {
		index, _, _ := uiSendMessage.Call(c.input, 0x147, 0, 0)
		if int(index) < 0 || int(index) >= len(c.options) {
			return ""
		}
		if c.name != "category" && c.name != "priority" && index == 0 {
			return ""
		}
		return c.options[int(index)]
	}
	buffer := make([]uint16, 2001)
	user32DLL.NewProc("GetWindowTextW").Call(c.input, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
	return normalizeTicketInput(windows.UTF16ToString(buffer))
}

func normalizeTicketInput(value string) string {
	return strings.TrimSpace(strings.ReplaceAll(value, "\r\n", "\n"))
}
func (f *ticketFormUI) answers() (map[string]string, map[string]string) {
	answers := map[string]string{}
	context := map[string]string{"branch": f.context["branch"], "category": f.value(f.controls[1]), "priority": f.value(f.controls[2])}
	for i, field := range f.definition.Fields {
		if helpdeskFieldVisible(field, answers, context) {
			answers[field.ID] = f.value(f.controls[i+4])
		}
	}
	return answers, context
}
func (f *ticketFormUI) layout() {
	if f.updating {
		return
	}
	f.updating = true
	defer func() { f.updating = false }()
	answers, context := f.answers()
	top := int32(0)
	for i := range f.controls {
		c := &f.controls[i]
		c.visible = i < 4 || helpdeskFieldVisible(f.definition.Fields[i-4], answers, context)
		if c.visible {
			c.top = top
			top += f.u.px(28) + c.height + f.u.px(18)
		}
	}
	f.total = top
	f.scrollTo(f.offset)
}
func (f *ticketFormUI) scrollTo(position int32) {
	maximum := f.total - f.page
	if maximum < 0 {
		maximum = 0
	}
	if position < 0 {
		position = 0
	}
	if position > maximum {
		position = maximum
	}
	f.offset = position
	w := f.u.width - f.u.px(76)
	for _, c := range f.controls {
		show := uintptr(0)
		if c.visible {
			show = 5
		}
		user32DLL.NewProc("MoveWindow").Call(c.label, 0, uintptr(c.top-position), uintptr(w), uintptr(f.u.px(24)), 1)
		h := c.height
		if len(c.options) > 0 {
			h = f.u.px(200)
		}
		x, y, width := f.u.px(12), c.top+f.u.px(38)-position, w-f.u.px(24)
		if len(c.options) > 0 {
			x = 0
			y = c.top + f.u.px(28) - position
			width = w
		} else {
			h -= f.u.px(20)
		}
		user32DLL.NewProc("MoveWindow").Call(c.input, uintptr(x), uintptr(y), uintptr(width), uintptr(h), 1)
		uiShowWindow.Call(c.label, show)
		uiShowWindow.Call(c.input, show)
	}
	f.u.refreshScroll()
	user32DLL.NewProc("InvalidateRect").Call(f.panel, 0, 1)
}
func (f *ticketFormUI) changed(source, code uintptr) bool {
	for _, c := range f.controls {
		if source != c.input {
			continue
		}
		if (len(c.options) > 0 && code == 1) || (len(c.options) == 0 && code == 0x300) {
			f.layout()
		}
		if (len(c.options) > 0 && code == 3) || (len(c.options) == 0 && code == 0x100) {
			if c.top < f.offset {
				f.scrollTo(c.top)
			} else if c.top+f.u.px(28)+c.height > f.offset+f.page {
				f.scrollTo(c.top + f.u.px(28) + c.height - f.page)
			}
		}
		if code == 3 || code == 4 || code == 0x100 || code == 0x200 {
			user32DLL.NewProc("InvalidateRect").Call(f.panel, 0, 0)
		}
		return true
	}
	return false
}
func validateTicketForm(request supportRequest, definition helpdeskForm, context map[string]string) (string, string) {
	if strings.TrimSpace(request.Subject) == "" || len(request.Subject) > 160 {
		return "subject", "Enter a short subject (up to 160 bytes)."
	}
	if validateSupportMessage(request.Message) != nil {
		return "description", "Describe the issue (up to 2000 bytes)."
	}
	answers := map[string]string{}
	for _, field := range definition.Fields {
		if !helpdeskFieldVisible(field, answers, context) {
			continue
		}
		value := request.Fields[field.ID]
		if len(value) > 500 || (field.Required && value == "") {
			return field.ID, fmt.Sprintf("Check %s: %s", field.Label, "an answer is required if marked * (up to 500 bytes).")
		}
		if field.Type == "select" && value != "" {
			valid := false
			for _, option := range field.Options {
				valid = valid || value == option
			}
			if !valid {
				return field.ID, "Choose an available option for " + field.Label + "."
			}
		}
		answers[field.ID] = value
	}
	return "", ""
}
func (f *ticketFormUI) submit() bool {
	answers, context := f.answers()
	r := *f.request
	r.Subject = f.value(f.controls[0])
	r.Category = context["category"]
	r.Priority = context["priority"]
	r.Message = f.value(f.controls[3])
	r.Fields = answers
	field, message := validateTicketForm(r, f.definition, context)
	if message != "" {
		f.u.footer = message
		user32DLL.NewProc("InvalidateRect").Call(f.u.window, 0, 1)
		for _, c := range f.controls {
			if c.name == field {
				f.scrollTo(c.top)
				uiSetFocus.Call(c.input)
				break
			}
		}
		return false
	}
	*f.request = r
	return true
}
func ticketPanelProc(hwnd uintptr, message uint32, wParam, lParam uintptr) uintptr {
	f := currentTicketForm
	if f == nil || f.u == nil || f.original == 0 {
		result, _, _ := uiDefWindow.Call(hwnd, uintptr(message), wParam, lParam)
		return result
	}
	switch message {
	case 0x111:
		result, _, _ := uiSendMessage.Call(f.u.window, uintptr(message), wParam, lParam)
		return result
	case 0x133, 0x134, 0x138:
		uiBackgroundMode.Call(wParam, 1)
		if message == 0x138 {
			uiTextColor.Call(wParam, 0x00c6bba4)
			gdi32DLL.NewProc("SetBkColor").Call(wParam, 0x0042351e)
			return f.u.bodyBrush
		}
		uiTextColor.Call(wParam, 0x00f9f7ed)
		gdi32DLL.NewProc("SetBkColor").Call(wParam, 0x00362b17)
		return f.inputBrush
	case 0x2c: // WM_MEASUREITEM
		if lParam != 0 {
			item := (*ticketMeasureItem)(unsafe.Pointer(lParam))
			item.Height = uint32(f.u.px(32))
			return 1
		}
	case 0x2b: // WM_DRAWITEM, native dropdown rows
		if lParam != 0 {
			f.paintChoice((*workspaceDrawItem)(unsafe.Pointer(lParam)))
			return 1
		}
	case 0xf:
		var paint uiPaint
		dc, _, _ := uiBeginPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		f.paintFields(dc)
		uiEndPaint.Call(hwnd, uintptr(unsafe.Pointer(&paint)))
		return 0
	case 0x115:
		position := f.offset
		switch wParam & 0xffff {
		case 0:
			position -= f.u.px(32)
		case 1:
			position += f.u.px(32)
		case 2:
			position -= f.page
		case 3:
			position += f.page
		case 4, 5:
			info := ticketScrollInfo{Mask: 0x10}
			info.Size = uint32(unsafe.Sizeof(info))
			user32DLL.NewProc("GetScrollInfo").Call(hwnd, 1, uintptr(unsafe.Pointer(&info)))
			position = info.Track
		case 6:
			position = 0
		case 7:
			position = f.total
		}
		f.scrollTo(position)
		return 0
	case 0x20a:
		f.scrollTo(f.offset - int32(int16(wParam>>16))*f.u.px(48)/120)
		return 0
	}
	result, _, _ := user32DLL.NewProc("CallWindowProcW").Call(f.original, hwnd, uintptr(message), wParam, lParam)
	return result
}
