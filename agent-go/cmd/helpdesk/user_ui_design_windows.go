package main

// Shared styling for consent, helpdesk, Home confirmation and notifications.
// These routines draw controls only; they cannot approve or dispatch actions.
func (u *wardenUI) validAction(id, source uintptr) bool {
	if source == 0 {
		return false
	}
	if id == 6 {
		return u.approval && u.allow != 0 && source == u.allow
	}
	return (id == 1 || id == 7) && u.deny != 0 && source == u.deny
}

func (u *wardenUI) surface() *workspaceSurface {
	s := workspaceNewSurface(u.width, u.height)
	if s == nil {
		return nil
	}
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, 0xff172b36)
	pad := u.px(24)
	// Quiet branding and an explicit purpose, not a generic Windows popup.
	s.circle(pad, u.px(22), u.px(32), 0xff315564)
	s.wardenMark(pad+u.px(2), u.px(24), u.px(28), 0xffdeeff2)
	s.textLeft("WARDEN", pad+u.px(44), u.px(20), u.width-pad*2-u.px(44), u.px(22), u.font, 0xffdeeff2)
	kind := "NOTIFICATION"
	if u.approval {
		kind = "YOUR APPROVAL REQUIRED"
	}
	if u.deletion {
		kind = "HOME FILE CONFIRMATION"
	}
	if u.support {
		kind = "CONTACT YOUR IT TEAM"
	}
	s.textLeft(kind, pad+u.px(44), u.px(43), u.width-pad*2-u.px(44), u.px(16), u.smallFont, 0xff91abb8)
	s.textLeft(u.instruction, pad, u.px(82), u.width-pad*2, u.px(62), u.headingFont, 0xffedf7f9)
	accent := uint32(0xff70becb)
	if u.severity == "warning" {
		accent = 0xffe4ba75
	}
	if u.severity == "critical" {
		accent = 0xffef9c9c
	}
	// Inset reading/writing surface with a severity accent, kept scrollable.
	s.roundedRect(pad-u.px(6), u.px(140), u.width-pad*2+u.px(12), u.height-u.px(256), u.px(12), 0xff304d5c)
	s.roundedRect(pad-u.px(5), u.px(141), u.width-pad*2+u.px(10), u.height-u.px(258), u.px(11), 0xff1e3542)
	s.roundedRect(pad+u.px(4), u.px(151), u.px(3), u.height-u.px(280), u.px(1), accent)
	s.textLeft(u.footer, pad, u.height-u.px(112), u.width-pad*2, u.px(49), u.smallFont, 0xffa4bbc6)
	return s
}
func (u *wardenUI) paint(dc uintptr) {
	s := u.surface()
	if s == nil {
		u.fill(dc, uiRect{0, 0, u.width, u.height}, 0x00362b17)
		u.text(dc, u.instruction, uiRect{u.px(24), u.px(82), u.width - u.px(24), u.px(144)}, u.headingFont, 0x00f9f7ed)
		return
	}
	defer s.close()
	workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
	gdi32DLL.NewProc("BitBlt").Call(dc, 0, 0, uintptr(u.width), uintptr(u.height), s.dc, 0, 0, 0x00cc0020)
}
func (u *wardenUI) paintButton(item *workspaceDrawItem) {
	w, h := item.Rect.Right-item.Rect.Left, item.Rect.Bottom-item.Rect.Top
	s := workspaceNewSurface(w, h)
	if s == nil {
		return
	}
	defer s.close()
	workspaceGDIPlus.NewProc("GdipGraphicsClear").Call(s.graphics, 0xff172b36)
	primary := item.ControlID == 6
	fill, rim, text := uint32(0xff263f4d), uint32(0xff55707f), uint32(0xffe7f2f5)
	if primary {
		fill, rim = 0xff2b6979, 0xff7cb9c7
	}
	if primary && u.deletion {
		fill, rim = 0xff6a4141, 0xffd69d9d
	}
	if item.State&1 != 0 {
		fill = 0xff1f3b48
	}
	if item.State&0x10 != 0 {
		rim = 0xffbceaf0
	}
	s.roundedRect(0, 0, w, h, u.px(10), rim)
	s.roundedRect(1, 1, w-2, h-2, u.px(9), fill)
	label := u.denyLabel
	if primary {
		label = u.allowLabel
	}
	s.text(label, u.px(6), 0, w-u.px(12), h, u.font, text)
	workspaceGDIPlus.NewProc("GdipFlush").Call(s.graphics, 1)
	gdi32DLL.NewProc("BitBlt").Call(item.DC, uintptr(item.Rect.Left), uintptr(item.Rect.Top), uintptr(w), uintptr(h), s.dc, 0, 0, 0x00cc0020)
}
