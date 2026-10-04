package main

import ("strings";"time";"golang.org/x/sys/windows")

var supportInputOptions []string
var supportInputSubmitLabel string
func helpdeskInput(title, content, footer, label string, options []string) (string, bool) {
	supportInputOptions = options
	supportInputSubmitLabel = label
	supportMessageFromUI = ""
	defer func() { supportInputOptions = nil; supportInputSubmitLabel = "" }()
	if runWardenUserDialog("Warden Support", title, content, footer, "info", true) != 0 {
		return "", false
	}
	return strings.TrimSpace(supportMessageFromUI), true
}
func helpdeskNotice(title, message string, ok bool) {
	severity := "warning"
	if ok {
		severity = "info"
	}
	runWardenUserDialog("Warden Helpdesk", title, message, "No remote access has been granted.", severity, false)
}
func helpdeskDialogMutex() (windows.Handle, error) {
	return windows.CreateMutex(nil, false, uiString("Local\\WardenSupportDialog.v1"))
}
func runHelpdeskCreate(message string) int {
	mutex, err := helpdeskDialogMutex()
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if err != nil {
		return 2
	}
	form, err := exchangeSupportRequest(supportRequest{Action: "form"})
	if err != nil || !form.OK || form.Data == nil || len(form.Data.Form.Categories) == 0 {
		helpdeskNotice("Helpdesk unavailable", "The ticket form could not be loaded. Check connectivity or contact your IT team.", false)
		return 1
	}
	definition := form.Data.Form
	request := supportRequest{Action: "create", RequestID: newSupportID(), Fields: map[string]string{}}
	if request.RequestID == "" {
		return 1
	}
	request.Priority = "normal"
	request.Message = message
	if !runTicketForm(definition, form.Data.Context, &request) {
		return 2
	}
	// Reuse the same UUID on retries: an uncertain network result cannot create
	// duplicate tickets. The user explicitly chooses retry, never automatic spam.
	for {
		result, sendErr := exchangeSupportRequest(request)
		if sendErr == nil && result.OK {
			helpdeskNotice("Ticket created", "#"+strings.ToUpper(result.RequestID[:min(8, len(result.RequestID))])+"\n"+result.Message, true)
			return 0
		}
		choice, again := helpdeskInput("Ticket not confirmed", "Your ticket was not confirmed. A network interruption may have occurred after it reached the server.", "Retry uses the same ticket identifier and cannot create a second copy.", "Continue", []string{"Retry", "Close"})
		if !again || choice != "Retry" {
			return 1
		}
	}
}
func helpdeskLocalTime(value string) string {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value
	}
	return parsed.Local().Format("02 Jan 2006 15:04 MST")
}
func helpdeskConversation(ticket helpdeskTicket, data *helpdeskData) string {
	text := "#" + ticket.Number + " · " + ticket.Subject + "\nStatus: " + ticket.Status + " · " + ticket.Priority + "\nArrangement: " + ticket.Mode
	if ticket.Visit != nil {
		text += "\nVisit: " + helpdeskLocalTime(*ticket.Visit)
	}
	text += "\n\nOriginal request\n" + data.Description
	for _, entry := range data.Thread {
		text += "\n\n" + entry.Author + " · " + helpdeskLocalTime(entry.Created) + "\n" + entry.Message
	}
	return text
}
func runHelpdeskTickets() int {
	mutex, err := helpdeskDialogMutex()
	if mutex != 0 {
		defer windows.CloseHandle(mutex)
	}
	if err != nil {
		return 2
	}
	result, err := exchangeSupportRequest(supportRequest{Action: "list"})
	if err != nil || !result.OK || result.Data == nil {
		helpdeskNotice("Helpdesk unavailable", "Tickets could not be loaded. Check connectivity and try again.", false)
		return 1
	}
	if len(result.Data.Tickets) == 0 {
		helpdeskNotice("My tickets", "No tickets were found for your signed-in Windows account.", true)
		return 0
	}
	options := []string{}
	for _, ticket := range result.Data.Tickets {
		options = append(options, "#"+ticket.Number+" · "+ticket.Subject+" ["+ticket.Status+"]")
	}
	selected, ok := helpdeskInput("My tickets", "Choose a ticket to read the conversation or send a reply.", "Only your Windows account's latest 20 tickets are shown.", "Open ticket", options)
	if !ok {
		return 2
	}
	ticket := result.Data.Tickets[0]
	for i, option := range options {
		if option == selected {
			ticket = result.Data.Tickets[i]
			break
		}
	}
	page := 0
	for {
		detail, detailErr := exchangeSupportRequest(supportRequest{Action: "detail", RequestID: ticket.ID, Page: page})
		if detailErr != nil || !detail.OK || detail.Data == nil || len(detail.Data.Tickets) == 0 {
			helpdeskNotice("Ticket unavailable", "This ticket could not be loaded.", false)
			return 1
		}
		ticket = detail.Data.Tickets[0]
		actions := []string{"Refresh", "Close"}
		if ticket.Status == "resolved" {
			actions = append([]string{"Reopen"}, actions...)
		} else {
			actions = append([]string{"Reply"}, actions...)
		}
		if detail.Data.HasMore {
			actions = append(actions, "Older messages")
		}
		if page > 0 {
			actions = append(actions, "Latest messages")
		}
		choice, proceed := helpdeskInput("#"+ticket.Number+" · Conversation", helpdeskConversation(ticket, detail.Data), "Reading or replying never grants remote access.", "Continue", actions)
		if !proceed || choice == "Close" {
			return 0
		}
		switch choice {
		case "Older messages":
			page++
		case "Latest messages":
			page = 0
		case "Reopen":
			response, sendErr := exchangeSupportRequest(supportRequest{Action: "reopen", RequestID: ticket.ID})
			helpdeskNotice("Reopen ticket", response.Message, sendErr == nil && response.OK)
			page = 0
		case "Reply":
			value, send := helpdeskInput("#"+ticket.Number+" · Reply", "", "Your reply is visible to IT support. Do not include credentials.", "Send reply", nil)
			if !send {
				continue
			}
			if validateSupportMessage(value) != nil {
				helpdeskNotice("Check your reply", "Enter a reply of at most 2000 bytes.", false)
				continue
			}
			reply := supportRequest{Action: "reply", RequestID: ticket.ID, MessageID: newSupportID(), Message: value}
			if reply.MessageID == "" {
				return 1
			}
			for {
				response, sendErr := exchangeSupportRequest(reply)
				if sendErr == nil && response.OK {
					helpdeskNotice("Reply sent", response.Message, true)
					break
				}
				choice, retry := helpdeskInput("Reply not confirmed", "The reply was not confirmed. The ticket may be resolved or connectivity may be interrupted.", "Retry reuses the same message identifier.", "Continue", []string{"Retry", "Close"})
				if !retry || choice != "Retry" {
					break
				}
			}
			page = 0
		}
	}
}
