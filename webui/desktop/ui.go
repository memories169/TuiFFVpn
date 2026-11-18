// fxvpn-desktop — native Linux GUI for the Firefox VPN console.
// Copyright (C) 2026
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// SPDX-License-Identifier: GPL-3.0-only

package desktop

// The main window: a Macchiato-styled Gio UI with four tabs.
//
//	Trạng thái — proxy state, connect/disconnect, quick test
//	Account    — unlimited account list, add (login/2FA/tokens), refresh-all
//	Vị trí      — country/city/server picker, connect
//	Test       — exit-IP diagnostics through the tunnel
//
// The engine runs in-process; widgets call Engine methods on the UI thread
// only for snapshot reads, and push long operations onto goroutines that
// report back through a channel so the frame loop never blocks.

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"io"
	"strings"
	"sync"
	"time"

	"gioui.org/app"
	"gioui.org/io/clipboard"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"fxsocks/webui/internal/webapp"
)

// uiEvent is the async-op completion signal (widgets never block).
type uiEvent func()

// UI holds all window state.
type UI struct {
	engine *Engine
	window *app.Window
	ops    *op.Ops
	theme  *material.Theme
	// frameCtx is the gtx of the current frame — handleClicks uses it for
	// Clicked(gtx) (Gio v0.8 API).
	frameCtx layout.Context

	events chan uiEvent

	// tabs
	tabs       []string
	tabButtons widget.Enum
	tabClicks  map[string]*widget.Clickable

	// status tab
	connectBtn   widget.Clickable
	disconnect   widget.Clickable
	quickTest    widget.Clickable
	statusCached StatusSnapshot
	statusAt     time.Time

	// accounts tab
	emailEdit         widget.Editor
	passEdit          widget.Editor
	codeEdit          widget.Editor
	session           string // pending 2FA session token
	addBtn            widget.Clickable
	verifyBtn         widget.Clickable
	addTokenBtn       widget.Clickable
	tokenAccess       widget.Editor
	tokenRefr         widget.Editor
	refreshAll        widget.Clickable
	accList           widget.List
	accRows           []AccountRow
	accAt             time.Time
	refreshAllRunning bool
	rowClicks         map[int]*widget.Clickable
	rowDel            map[int]*widget.Clickable
	// browser sign-in (FoxyVPN flow — no userscript)
	accMsg    string
	accMsgErr bool
	accMsgMu  sync.Mutex

	// locations tab
	refreshLocs  widget.Clickable
	locList      widget.List
	locRows      []Location
	locAt        time.Time
	locClicks    map[int]*widget.Clickable
	locLoadBusy  bool
	locConnectId string
	locMsg       string
	locMsgErr    bool

	// test tab
	testBtn   widget.Clickable
	wgConnect widget.Clickable
	wgStop    widget.Clickable
	wgBusy    bool
	wgStatus  string
	testRes   *webapp.TestResult
	logsEdit  widget.Editor
	logsCopy  widget.Clickable
	logsClear widget.Clickable
	keyCopy   widget.Clickable
	testBusy  bool
	testMsg   string

	toast     string
	toastErr  bool
	toastAt   time.Time
	toastOnce sync.Once
}

// NewUI wires the window.
func NewUI(e *Engine) *UI {
	return &UI{
		engine:    e,
		ops:       &op.Ops{},
		events:    make(chan uiEvent, 32),
		tabs:      []string{"Trạng thái", "Account", "Vị trí", "Test", "Logs"},
		tabClicks: map[string]*widget.Clickable{},
		rowClicks: map[int]*widget.Clickable{},
		rowDel:    map[int]*widget.Clickable{},
		locClicks: map[int]*widget.Clickable{},
		accList:   widget.List{List: layout.List{Axis: layout.Vertical}},
		locList:   widget.List{List: layout.List{Axis: layout.Vertical}},
	}
}

// SetWindow assigns the app window (called before Run).
func (u *UI) SetWindow(w *app.Window) { u.window = w }

// Run drives the event loop until the window closes.
func (u *UI) Run() error {
	w := u.window
	// Warm the caches in the background; the first frame shows instantly.
	go u.refreshAccounts()
	go u.refreshLocations(false)
	go u.refreshStatus()

	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(u.ops, e)
			u.frameCtx = gtx
			u.drainEvents()
			u.handleClicks()
			u.layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

// drainEvents runs queued UI updates (never blocks the frame).
func (u *UI) drainEvents() {
	for {
		select {
		case fn := <-u.events:
			fn()
		default:
			return
		}
	}
}

// handleClicks dispatches every clickable fired this frame.
func (u *UI) handleClicks() {
	// Tabs.
	for id, c := range u.tabClicks {
		if c.Clicked(u.frameCtx) {
			u.tabButtons.Value = id
			go u.refreshStatus()
		}
	}
	// Status tab.
	if u.connectBtn.Clicked(u.frameCtx) {
		u.reconnect()
	}
	if u.disconnect.Clicked(u.frameCtx) {
		u.async(func() { u.engine.Disconnect() })
		u.toastMsg("Đã yêu cầu ngắt kết nối", false)
	}
	if u.quickTest.Clicked(u.frameCtx) {
		u.testMsg = ""
		go u.doTest()
	}
	// Accounts tab.
	if u.addBtn.Clicked(u.frameCtx) {
		if u.session != "" {
			go u.doVerify()
		} else {
			go u.doAddAccount()
		}
	}
	if u.addTokenBtn.Clicked(u.frameCtx) {
		go u.doAddTokens()
	}
	if u.logsCopy.Clicked(u.frameCtx) {
		u.frameCtx.Execute(clipboard.WriteCmd{
			Type: "application/text",
			Data: io.NopCloser(strings.NewReader(u.engine.RecentLogs())),
		})
		u.toastMsg("Đã copy log vào clipboard", false)
	}
	if u.logsClear.Clicked(u.frameCtx) {
		u.engine.ClearLogs()
		u.toastMsg("Đã xoá log", false)
	}
	if u.keyCopy.Clicked(u.frameCtx) {
		u.frameCtx.Execute(clipboard.WriteCmd{
			Type: "application/text",
			Data: io.NopCloser(strings.NewReader(u.engine.IngestKey())),
		})
		u.toastMsg("Đã copy ingest key — dán vào INGEST_KEY trong userscript (một lần, key không đổi)", false)
	}
	if u.refreshAll.Clicked(u.frameCtx) {
		go u.doRefreshAll()
	}
	for i, c := range u.rowClicks {
		if c.Clicked(u.frameCtx) && i < len(u.accRows) {
			email := u.accRows[i].Email
			u.toastMsg("Đang chuyển sang "+email+"…", false)
			go func() {
				err := u.engine.SelectAccount(email)
				u.events <- func() {
					if err != nil {
						u.accMsg = "Chuyển account thất bại: " + err.Error()
						u.accMsgErr = true
					} else {
						u.accMsg = "Đang dùng " + email
						u.accMsgErr = false
					}
				}
				go u.refreshAccounts()
				go u.refreshStatus()
			}()
		}
	}
	for i, c := range u.rowDel {
		if c.Clicked(u.frameCtx) && i < len(u.accRows) {
			email := u.accRows[i].Email
			go func() {
				err := u.engine.DeleteAccount(email)
				u.events <- func() {
					if err != nil {
						u.accMsg = "Xoá thất bại: " + err.Error()
						u.accMsgErr = true
					} else {
						u.accMsg = "Đã xoá " + email
						u.accMsgErr = false
					}
				}
				go u.refreshAccounts()
				go u.refreshStatus()
			}()
		}
	}
	// Locations tab.
	if u.refreshLocs.Clicked(u.frameCtx) {
		go u.refreshLocations(true)
	}
	for i, c := range u.locClicks {
		if c.Clicked(u.frameCtx) && i < len(u.locRows) {
			loc := u.locRows[i]
			go u.doConnect(loc)
		}
	}
	// Test tab.
	if u.testBtn.Clicked(u.frameCtx) && !u.testBusy {
		go u.doTest()
	}
	// WireGuard.
	if u.wgConnect.Clicked(u.frameCtx) && !u.wgBusy {
		u.wgBusy = true
		u.wgStatus = "⏳ Đang đăng ký device + kết nối…"
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
			defer cancel()
			err := u.engine.ConnectWG(ctx)
			u.events <- func() {
				u.wgBusy = false
				if err != nil {
					u.wgStatus = "❌ " + err.Error()
				} else {
					st := u.engine.WGStatus()
					u.wgStatus = fmt.Sprintf("✅ WireGuard đã kết nối — tunnel %v", st["tunnel_ipv4"])
				}
			}
		}()
	}
	if u.wgStop.Clicked(u.frameCtx) && !u.wgBusy {
		u.engine.StopWG()
		u.wgStatus = "⏹ Đã ngắt WireGuard"
	}
}

// reconnect re-selects the stored location (restarts the tunnel).
func (u *UI) reconnect() {
	s := u.statusCached
	if s.Server == "" {
		u.toastMsg("Chưa chọn máy chủ — mở tab Vị trí", true)
		return
	}
	loc := Location{Country: s.Country, City: s.City, Host: s.Server}
	u.toastMsg("Đang kết nối lại…", false)
	go func() {
		// Resolve port from the cached locations, falling back to 443.
		port := 0
		locs, err := u.engine.Locations(context.Background(), false)
		if err == nil {
			for _, l := range locs {
				if l.Host == loc.Host {
					port = l.Port
					break
				}
			}
		}
		if port == 0 {
			port = 443
		}
		loc.Port = port
		if err := u.engine.Connect(context.Background(), loc); err != nil {
			u.events <- func() { u.toastMsg("Kết nối lại thất bại: "+err.Error(), true) }
			return
		}
		u.events <- func() { u.toastMsg("Đã kết nối lại: "+loc.City+", "+loc.Country, false) }
		go u.refreshStatus()
	}()
}

// toastMsg sets the footer toast (UI thread only).
func (u *UI) toastMsg(msg string, isErr bool) {
	u.toast = msg
	u.toastErr = isErr
	u.toastAt = time.Now()
	u.toastOnce = sync.Once{}
}

// async runs fn off the UI thread, then delivers its completion event.
func (u *UI) async(fn func()) {
	go func() {
		fn()
		u.events <- func() {}
	}()
}

// ---- background refreshers (call from goroutines only) ----

func (u *UI) refreshStatus() {
	s := u.engine.Status()
	u.events <- func() {
		u.statusCached = s
		u.statusAt = time.Now()
	}
}

func (u *UI) refreshAccounts() {
	rows := u.engine.Accounts()
	running := u.engine.RefreshAllRunning()
	u.events <- func() {
		u.accRows = rows
		u.accAt = time.Now()
		u.refreshAllRunning = running
	}
}

func (u *UI) refreshLocations(force bool) {
	// Marshalled through events so locLoadBusy flips on the UI thread.
	u.events <- func() { u.locLoadBusy = true }
	locs, err := u.engine.Locations(context.Background(), force)
	u.events <- func() {
		u.locLoadBusy = false
		if err != nil {
			u.locMsg = "Không tải được danh sách máy chủ: " + err.Error()
			u.locMsgErr = true
			return
		}
		u.locRows = locs
		u.locAt = time.Now()
		u.locMsg = ""
	}
}

func (u *UI) doConnect(loc Location) {
	u.events <- func() {
		u.locConnectId = loc.Host
		u.locMsg = "Đang kết nối tới " + loc.City + ", " + loc.Country + "…"
		u.locMsgErr = false
	}
	err := u.engine.Connect(context.Background(), loc)
	u.events <- func() {
		u.locConnectId = ""
		if err != nil {
			u.locMsg = "Kết nối thất bại: " + err.Error()
			u.locMsgErr = true
		} else {
			u.locMsg = "Đã kết nối: " + loc.City + ", " + loc.Country + " (" + loc.Host + ")"
			u.locMsgErr = false
		}
		go u.refreshStatus()
	}
}

func (u *UI) doTest() {
	u.events <- func() { u.testBusy = true }
	res := u.engine.TestProxy()
	u.events <- func() {
		u.testBusy = false
		u.testRes = &res
	}
}

func (u *UI) doAddAccount() {
	email := strings.TrimSpace(u.emailEdit.Text())
	pass := u.passEdit.Text()
	code := strings.TrimSpace(u.codeEdit.Text())
	if email == "" {
		u.setAccMsg("Nhập email Firefox account", true)
		return
	}
	needsCode, session, err := u.engine.AddAccount(context.Background(), email, pass, u.session, code)
	if err != nil {
		if strings.Contains(err.Error(), "captcha") || strings.Contains(err.Error(), "Fastly") {
			u.setAccMsg("Fastly đang chặn: đăng nhập trên trình duyệt rồi dán cặp token (ô token dưới đây).", true)
		} else {
			u.setAccMsg("Đăng nhập thất bại: "+err.Error(), true)
		}
		return
	}
	if needsCode {
		u.events <- func() { u.session = session }
		u.setAccMsg("Nhập mã xác minh từ email rồi bấm \"Gửi mã xác minh\"", false)
		return
	}
	u.events <- func() {
		u.session = ""
		u.emailEdit.SetText("")
		u.passEdit.SetText("")
		u.codeEdit.SetText("")
	}
	u.setAccMsg("Đã thêm "+email, false)
	go u.refreshAccounts()
}

func (u *UI) doVerify() {
	code := strings.TrimSpace(u.codeEdit.Text())
	session := u.session
	if session == "" || code == "" {
		u.setAccMsg("Nhập mã xác minh", true)
		return
	}
	_, _, err := u.engine.AddAccount(context.Background(), "", "", session, code)
	if err != nil {
		u.setAccMsg("Xác minh thất bại: "+err.Error(), true)
		return
	}
	u.events <- func() { u.session = "" }
	u.setAccMsg("Đã xác minh và thêm account", false)
	go u.refreshAccounts()
}

func (u *UI) doAddTokens() {
	email := strings.TrimSpace(u.emailEdit.Text())
	access := strings.TrimSpace(u.tokenAccess.Text())
	refresh := strings.TrimSpace(u.tokenRefr.Text())
	if email == "" {
		u.setAccMsg("Nhập email để gắn token", true)
		return
	}
	if err := u.engine.AddAccountWithTokens(email, access, refresh, 0); err != nil {
		u.setAccMsg("Lỗi: "+err.Error(), true)
		return
	}
	u.events <- func() {
		u.tokenAccess.SetText("")
		u.tokenRefr.SetText("")
	}
	u.setAccMsg("Đã thêm token cho "+email, false)
	go u.refreshAccounts()
}

func (u *UI) doRefreshAll() {
	if !u.engine.RefreshAll() {
		u.setAccMsg("Một đợt refresh đang chạy rồi — chờ xong nhé", true)
		return
	}
	u.setAccMsg("Đang refresh token của tất cả account…", false)
	// Poll until the pass finishes, refreshing rows as states land.
	go func() {
		deadline := time.Now().Add(15 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(4 * time.Second)
			running := u.engine.RefreshAllRunning()
			u.refreshAccounts()
			if !running {
				u.setAccMsg("Hoàn tất refresh tất cả token", false)
				return
			}
		}
	}()
}

func (u *UI) setAccMsg(msg string, isErr bool) {
	u.events <- func() {
		u.accMsg = msg
		u.accMsgErr = isErr
	}
}

// ---- layout ----

func (u *UI) layout(gtx layout.Context) layout.Dimensions {
	// Window background.
	paint.Fill(gtx.Ops, Base)

	// Toast.
	if u.toast != "" && time.Since(u.toastAt) < 6*time.Second {
		u.toastOnce.Do(func() {})
	}

	// Root column.
	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return u.layoutTabs(gtx)
		}),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			switch u.tabButtons.Value {
			case "1":
				return u.layoutAccounts(gtx)
			case "2":
				return u.layoutLocations(gtx)
			case "3":
				return u.layoutTest(gtx)
			case "4":
				return u.layoutLogs(gtx)
			default:
				return u.layoutStatus(gtx)
			}
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return u.layoutFooter(gtx)
		}),
	)
}

func (u *UI) layoutTabs(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Max.Y = gtx.Dp(unit.Dp(52))
	background(gtx, Mantle)
	// Simple row of tab buttons with an accent underline on the active one.
	children := make([]layout.FlexChild, 0, len(u.tabs))
	for i, name := range u.tabs {
		i, name := i, name
		id := fmt.Sprint(i)
		if u.tabClicks[id] == nil {
			u.tabClicks[id] = &widget.Clickable{}
		}
		children = append(children, layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			btn := material.Button(u.th(), u.tabClicks[id], name)
			btn.Background = transparent
			btn.Color = Subtext1
			btn.TextSize = unit.Sp(14)
			if u.tabButtons.Value == id {
				btn.Color = Lavender
			}
			dims := btn.Layout(gtx)
			if u.tabButtons.Value == id {
				// underline
				r := image.Rectangle{Max: image.Point{X: dims.Size.X, Y: gtx.Dp(unit.Dp(3))}}
				offs := op.Offset(image.Point{Y: dims.Size.Y - gtx.Dp(unit.Dp(3))}).Push(gtx.Ops)
				paint.FillShape(gtx.Ops, Lavender, clip.Rect(r).Op())
				offs.Pop()
			}
			return dims
		}))
	}
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx, children...)
}

var transparent = color.NRGBA{}

func (u *UI) th() *material.Theme {
	if u.theme == nil {
		u.theme = macchiatoTheme(material.NewTheme())
		// Seed the shaper with the embedded DejaVu faces (full Vietnamese
		// coverage). The default zero shaper resolves text through the
		// system font scan only; when that fails — a bare-bones Wine
		// prefix is the reproducible case — the shaper emits no glyphs and
		// the window shows colored rectangles with no text. gofont (tried
		// first) proved insufficient: its cmap lacks Vietnamese diacritics
		// like ả ạ ế ữ ơ ư, so labels with those rendered blank even when
		// shaping "worked". See fonts.go.
		u.theme.Shaper = newShaper()
	}
	return u.theme
}

func (u *UI) layoutStatus(gtx layout.Context) layout.Dimensions {
	if time.Since(u.statusAt) > 2*time.Second {
		go u.refreshStatus()
	}
	s := u.statusCached
	in := material.Body1(u.th(), "SOCKS5: "+statusListen(s))
	in.Color = Subtext1

	title := material.H5(u.th(), "fxvpn — Firefox VPN")
	title.Color = Lavender

	return layout.UniformInset(unit.Dp(20)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(title.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(14)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				rows := []statusLine{
					{"Trạng thái", boolLabel(s.Running, "ĐANG CHẠY", "ĐANG DỪNG"), boolColor(s.Running)},
					{"Account", s.EmailOr("(chưa có)"), Text},
					{"Máy chủ", s.ServerOr("—"), Text},
					{"Vị trí", s.LocationOr("—"), Text},
					{"SOCKS5", statusListen(s), Text},
					{"Lỗi gần nhất", s.LastErrorOr("không"), Text},
				}
				kids := make([]layout.FlexChild, 0, len(rows))
				for _, ln := range rows {
					ln := ln
					kids = append(kids, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return statusRow(gtx, u.th(), ln.label, ln.value, ln.color)
					}))
				}
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx, kids...)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(22)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceEnd}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(u.th(), &u.connectBtn, "Kết nối lại")
						btn.Background = Lavender
						btn.Color = Crust
						return btn.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Width: unit.Dp(10)}.Layout(gtx) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(u.th(), &u.disconnect, "Ngắt kết nối")
						btn.Background = Surface0
						btn.Color = Red
						return btn.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Width: unit.Dp(10)}.Layout(gtx) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(u.th(), &u.quickTest, "Test nhanh")
						btn.Background = Surface0
						btn.Color = Sky
						return btn.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(16)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				body := material.Body2(u.th(), hintFor(s))
				body.Color = Overlay2
				return body.Layout(gtx)
			}),
		)
	})
}

func (u *UI) layoutFooter(gtx layout.Context) layout.Dimensions {
	background(gtx, Mantle)
	msg := u.footerText()
	lbl := material.Body2(u.th(), msg)
	if u.toastErr || u.accMsgErr || u.locMsgErr {
		lbl.Color = Peach
	} else {
		lbl.Color = Subtext0
	}
	return layout.UniformInset(unit.Dp(8)).Layout(gtx, lbl.Layout)
}

func (u *UI) footerText() string {
	if u.toast != "" && time.Since(u.toastAt) < 6*time.Second {
		return u.toast
	}
	if u.accMsg != "" {
		return u.accMsg
	}
	if u.locMsg != "" {
		return u.locMsg
	}
	if u.testMsg != "" {
		return u.testMsg
	}
	return "Sẵn sàng — state: " + u.engine.StatePath()
}

// account row rendering ----------------------------------------------------------------

func (u *UI) layoutAccounts(gtx layout.Context) layout.Dimensions {
	if time.Since(u.accAt) > 3*time.Second {
		go u.refreshAccounts()
	}
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// Add-account form.
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return u.editorLine(gtx, &u.emailEdit, "Email Firefox account")
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return u.editorLine(gtx, &u.passEdit, "Mật khẩu")
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx) }),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								label := "Đăng nhập"
								if u.session != "" {
									label = "Gửi mã xác minh"
								}
								btn := material.Button(u.th(), &u.addBtn, label)
								btn.Background = Lavender
								btn.Color = Crust
								return btn.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								return u.editorLine(gtx, &u.codeEdit, "Mã 2FA (nếu có)")
							}),
						)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(u.th(), &u.addTokenBtn, "Thêm bằng token")
						btn.Background = Surface0
						btn.Color = Teal
						return btn.Layout(gtx)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return u.editorLine(gtx, &u.tokenAccess, "Access token (tuỳ chọn)")
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						return u.editorLine(gtx, &u.tokenRefr, "Refresh token")
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(12)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						label := "🔄 Refresh token tất cả account"
						if u.refreshAllRunning {
							label = "🔄 Đang refresh…"
						}
						btn := material.Button(u.th(), &u.refreshAll, label)
						btn.Background = Surface1
						btn.Color = Yellow
						return btn.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						t := material.Body2(u.th(), fmt.Sprintf("%d account — không giới hạn", len(u.accRows)))
						t.Color = Subtext0
						return layout.Center.Layout(gtx, t.Layout)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(10)}.Layout(gtx) }),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				lst := material.List(u.th(), &u.accList)
				return lst.Layout(gtx, len(u.accRows), func(gtx layout.Context, i int) layout.Dimensions {
					return u.accountRow(gtx, i)
				})
			}),
		)
	})
}

func (u *UI) accountRow(gtx layout.Context, i int) layout.Dimensions {
	row := u.accRows[i]
	// lazily create clickables
	if u.rowClicks[i] == nil {
		u.rowClicks[i] = &widget.Clickable{}
		u.rowDel[i] = &widget.Clickable{}
	}
	bg := Surface0
	if row.Active {
		bg = withAlpha(Green, 30)
	}
	// Card per account: bordered, rounded, with a gap so accounts are
	// visually separated from each other.
	return widget.Border{
		Color:        Surface1,
		CornerRadius: unit.Dp(10),
		Width:        unit.Dp(1),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			background(gtx, bg)
			return layout.UniformInset(unit.Dp(12)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								t := material.Body1(u.th(), row.Email)
								t.Color = Text
								t.TextSize = unit.Sp(14)
								return t.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if row.Active {
									badge := material.Body2(u.th(), "● ĐANG DÙNG")
									badge.Color = Green
									badge.TextSize = unit.Sp(11)
									return badge.Layout(gtx)
								}
								return layout.Dimensions{}
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions { return layout.Dimensions{} }),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								if !row.Active && row.HasToken {
									btn := material.Button(u.th(), u.rowClicks[i], "Dùng")
									btn.Background = Surface1
									btn.Color = Lavender
									btn.TextSize = unit.Sp(12)
									btn.CornerRadius = unit.Dp(6)
									btn.Inset = layout.UniformInset(unit.Dp(6))
									return btn.Layout(gtx)
								}
								return layout.Dimensions{}
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								return layout.Spacer{Width: unit.Dp(6)}.Layout(gtx)
							}),
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								btn := material.Button(u.th(), u.rowDel[i], "✕")
								btn.Background = withAlpha(Red, 40)
								btn.Color = Red
								btn.TextSize = unit.Sp(14)
								btn.CornerRadius = unit.Dp(8)
								// Button-sized, not a cramped text sliver: match
								// the "Dùng" button's height and give the glyph
								// room to breathe.
								btn.Inset = layout.UniformInset(unit.Dp(12))
								return btn.Layout(gtx)
							}),
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
							layout.Rigid(func(gtx layout.Context) layout.Dimensions {
								t := material.Body2(u.th(), "Quota: "+quotaLabel(row))
								t.Color = Subtext0
								t.TextSize = unit.Sp(12)
								return t.Layout(gtx)
							}),
							layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
								if row.RefreshError != "" {
									t := material.Body2(u.th(), "⛔ token chết — thêm lại account")
									t.Color = Red
									t.TextSize = unit.Sp(12)
									t.Alignment = text.End
									return t.Layout(gtx)
								}
								if row.ProbeError != "" {
									t := material.Body2(u.th(), "⚠ Fastly chặn tạm thời — vẫn hoạt động")
									t.Color = Yellow
									t.TextSize = unit.Sp(12)
									t.Alignment = text.End
									return t.Layout(gtx)
								}
								if !row.RefreshedAt.IsZero() {
									t := material.Body2(u.th(), "✓ refresh "+row.RefreshedAt.Local().Format("15:04 02/01"))
									t.Color = Overlay2
									t.TextSize = unit.Sp(12)
									t.Alignment = text.End
									return t.Layout(gtx)
								}
								return layout.Dimensions{}
							}),
						)
					}),
				)
			})
		})
	})
}

// locations tab ------------------------------------------------------------------------

func (u *UI) layoutLogs(gtx layout.Context) layout.Dimensions {
	// Keep the editor text in sync with the ring (cheap: one string join).
	logs := u.engine.RecentLogs()
	if u.logsEdit.Text() != logs {
		u.logsEdit.SetText(logs)
	}
	if u.logsEdit.Text() == "" {
		u.logsEdit.SetText("(chưa có log)")
	}

	// Ingest key banner: the userscript pairing key — stable across
	// restarts (persisted in state.json), so userscript users only ever
	// paste it once.
	key := u.engine.IngestKey()

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return widget.Border{
				Color:        Surface1,
				CornerRadius: unit.Dp(8),
				Width:        unit.Dp(1),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				background(gtx, withAlpha(Lavender, 20))
				return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							t := material.Body2(u.th(), "Ingest key (userscript) — KHÔNG ĐỔI sau khi khởi động lại, chỉ cần dán vào INGEST_KEY một lần:")
							t.Color = Subtext1
							t.TextSize = unit.Sp(11)
							return t.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Spacer{Height: unit.Dp(6)}.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
								layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
									t := material.Body1(u.th(), key)
									t.Color = Lavender
									t.TextSize = unit.Sp(12)
									return t.Layout(gtx)
								}),
								layout.Rigid(func(gtx layout.Context) layout.Dimensions {
									btn := material.Button(u.th(), &u.keyCopy, "📋 Copy key")
									btn.Background = Lavender
									btn.Color = Crust
									btn.TextSize = unit.Sp(12)
									btn.CornerRadius = unit.Dp(6)
									btn.Inset = layout.UniformInset(unit.Dp(6))
									return btn.Layout(gtx)
								}),
							)
						}),
					)
				})
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx) }),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(u.th(), &u.logsCopy, "📋 Copy log")
					btn.Background = Surface1
					btn.Color = Sky
					return btn.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layout.Spacer{Width: unit.Dp(8)}.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(u.th(), &u.logsClear, "Xoá log")
					btn.Background = Surface0
					btn.Color = Overlay0
					return btn.Layout(gtx)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					t := material.Body2(u.th(), "Log engine (keeper/rotator/edge) — giống output của docker console")
					t.Color = Overlay0
					t.TextSize = unit.Sp(11)
					return layout.Center.Layout(gtx, t.Layout)
				}),
			)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx) }),
		layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
			return widget.Border{
				Color:        Surface1,
				CornerRadius: unit.Dp(8),
				Width:        unit.Dp(1),
			}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				background(gtx, Mantle)
				ed := material.Editor(u.th(), &u.logsEdit, "")
				ed.TextSize = unit.Sp(11)
				ed.Color = Subtext1
				return layout.UniformInset(unit.Dp(10)).Layout(gtx, ed.Layout)
			})
		}),
	)
}

func (u *UI) layoutLocations(gtx layout.Context) layout.Dimensions {
	if len(u.locRows) == 0 && !u.locLoadBusy {
		go u.refreshLocations(false)
	}
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(u.th(), &u.refreshLocs, "Tải lại danh sách")
						btn.Background = Surface0
						btn.Color = Sky
						return btn.Layout(gtx)
					}),
					layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
						t := material.Body2(u.th(), fmt.Sprintf("%d vị trí", len(u.locRows)))
						t.Color = Subtext0
						t.Alignment = text.End
						return t.Layout(gtx)
					}),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(10)}.Layout(gtx) }),
			layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
				lst := material.List(u.th(), &u.locList)
				return lst.Layout(gtx, len(u.locRows), func(gtx layout.Context, i int) layout.Dimensions {
					return u.locationRow(gtx, i)
				})
			}),
		)
	})
}

func (u *UI) locationRow(gtx layout.Context, i int) layout.Dimensions {
	loc := u.locRows[i]
	if u.locClicks[i] == nil {
		u.locClicks[i] = &widget.Clickable{}
	}
	busy := u.locConnectId == loc.Host
	// Connected = the status snapshot is running on THIS server host.
	st := u.statusCached
	connected := st.Running && st.Server == loc.Host
	bg := Surface0
	if busy {
		bg = withAlpha(Lavender, 50)
	} else if connected {
		bg = withAlpha(Green, 30)
	}
	return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		background(gtx, bg)
		btn := material.Button(u.th(), u.locClicks[i], "")
		btn.Background = transparent
		_ = btn
		return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							t := material.Body1(u.th(), loc.Country+" — "+loc.City)
							t.Color = Text
							t.TextSize = unit.Sp(14)
							return t.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							t := material.Body2(u.th(), loc.Host)
							t.Color = Overlay2
							t.TextSize = unit.Sp(11)
							return t.Layout(gtx)
						}),
						layout.Rigid(func(gtx layout.Context) layout.Dimensions {
							if connected && !busy {
								t := material.Body2(u.th(), "● Đang kết nối tới server này")
								t.Color = Green
								t.TextSize = unit.Sp(11)
								return t.Layout(gtx)
							}
							return layout.Dimensions{}
						}),
					)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					label := "Kết nối"
					if busy {
						label = "Đang kết nối…"
					} else if connected {
						label = "● Đã kết nối"
					}
					btn := material.Button(u.th(), u.locClicks[i], label)
					if connected && !busy {
						btn.Background = withAlpha(Green, 60)
						btn.Color = Crust
					} else {
						btn.Background = Lavender
						btn.Color = Crust
					}
					btn.TextSize = unit.Sp(12)
					btn.CornerRadius = unit.Dp(6)
					btn.Inset = layout.UniformInset(unit.Dp(6))
					return btn.Layout(gtx)
				}),
			)
		})
	})
}

// test tab -----------------------------------------------------------------------------

func (u *UI) layoutTest(gtx layout.Context) layout.Dimensions {
	return layout.UniformInset(unit.Dp(16)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			// WireGuard card — full-UDP tunnel mode.
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return u.layoutWGCard(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(18)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				title := material.Body1(u.th(), "Test đường truyền")
				title.Color = Mauve
				return title.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(8)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				btn := material.Button(u.th(), &u.testBtn, "Chạy test exit IP")
				btn.Background = Sapphire
				btn.Color = Crust
				return btn.Layout(gtx)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions { return layout.Spacer{Height: unit.Dp(14)}.Layout(gtx) }),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				if u.testBusy {
					t := material.Body1(u.th(), "Đang chạy test qua tunnel (tối đa 20s)…")
					t.Color = Subtext1
					return t.Layout(gtx)
				}
				if u.testRes == nil {
					t := material.Body1(u.th(), "Bấm test để kiểm tra lưu lượng đang đi qua tunnel VPN.")
					t.Color = Overlay2
					return t.Layout(gtx)
				}
				return u.testResultView(gtx, *u.testRes)
			}),
		)
	})
}

// layoutWGCard renders the WireGuard connect/stop controls + status.
func (u *UI) layoutWGCard(gtx layout.Context) layout.Dimensions {
	background(gtx, withAlpha(Mauve, 18))
	return layout.UniformInset(unit.Dp(14)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		title := material.Body1(u.th(), "WireGuard — UDP đầy đủ (device Guardian)")
		title.Color = Mauve
		hint := material.Body2(u.th(), "Tunnel WireGuard thật (userspace): udp:// trackers và DHT hoạt động, không bị edge chặn như đường MASQUE.")
		hint.Color = Overlay2

		connectLabel := "🔌 Kết nối WireGuard"
		if u.wgBusy {
			connectLabel = "⏳ Đang kết nối…"
		}
		connectBtn := material.Button(u.th(), &u.wgConnect, connectLabel)
		connectBtn.Background = Lavender
		connectBtn.Color = Crust
		connectBtn.TextSize = unit.Sp(12.5)
		stopBtn := material.Button(u.th(), &u.wgStop, "⏹ Ngắt")
		stopBtn.Background = Surface1
		stopBtn.Color = Text
		stopBtn.TextSize = unit.Sp(12.5)

		statusText := u.wgStatus
		if statusText == "" {
			st := u.engine.WGStatus()
			if st["connected"] == true {
				statusText = fmt.Sprintf("✅ Đã kết nối — tunnel %v", st["tunnel_ipv4"])
			} else if st["available"] == true {
				statusText = fmt.Sprintf("Device đã đăng ký: %v (%v) — chưa kết nối", st["device"], st["ipv4"])
			} else {
				statusText = "Chưa đăng ký device — bấm Kết nối để đăng ký với Guardian."
			}
		}
		status := material.Body2(u.th(), statusText)
		status.Color = Subtext0

		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(title.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(2)).Layout(gtx, hint.Layout)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(connectBtn.Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Spacer{Width: unit.Dp(10)}.Layout(gtx)
					}),
					layout.Rigid(stopBtn.Layout),
				)
			}),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layout.UniformInset(unit.Dp(4)).Layout(gtx, status.Layout)
			}),
		)
	})
}

func (u *UI) testResultView(gtx layout.Context, r webapp.TestResult) layout.Dimensions {
	bg := Surface0
	col := Green
	verdict := "THÀNH CÔNG — lưu lượng đang đi qua VPN"
	if !r.OK {
		bg = withAlpha(Red, 25)
		col = Red
		verdict = "THẤT BẠI — " + r.Error
	}
	return func(gtx layout.Context) layout.Dimensions {
		background(gtx, bg)
		return layout.UniformInset(unit.Dp(14)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			rows := []statusLine{
				{"Kết quả", verdict, col},
			}
			if r.OK {
				rows = append(rows,
					statusLine{"Exit IP", r.ExitIP, Text},
					statusLine{"Quốc gia", r.Country, Text},
					statusLine{"Độ trễ", fmt.Sprintf("%d ms", r.LatencyMS), Text},
					statusLine{"Máy chủ", r.Server, Text},
					statusLine{"Edge sessions", fmt.Sprint(r.EdgeSessions), Subtext1},
				)
				if r.SecondIP != "" && r.SecondIP != r.ExitIP {
					rows = append(rows, statusLine{"IP tunnel thứ hai", r.SecondIP + "  (edge gán IP theo tunnel — IP có thể xoay)", Yellow})
				}
				if r.EdgeSuspect {
					rows = append(rows, statusLine{"Cảnh báo", "Edge đang chặn tunnel — đổi máy chủ khác", Yellow})
				}
			}
			children := make([]layout.FlexChild, 0, len(rows))
			for _, ln := range rows {
				ln := ln
				children = append(children, layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return statusRow(gtx, u.th(), ln.label, ln.value, ln.color)
				}))
			}
			return layout.Flex{Axis: layout.Vertical}.Layout(gtx, children...)
		})
	}(gtx)
}

// ---- shared widgets ----

type statusLine struct {
	label, value string
	color        color.NRGBA
}

func statusRow(gtx layout.Context, th *material.Theme, label, value string, valueColor color.NRGBA) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			t := material.Body2(th, label)
			t.Color = Overlay1
			t.TextSize = unit.Sp(13)
			return layout.Inset{Bottom: unit.Dp(6), Right: unit.Dp(24)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(110))
				return t.Layout(gtx)
			})
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			t := material.Body2(th, value)
			t.Color = valueColor
			t.TextSize = unit.Sp(13)
			return t.Layout(gtx)
		}),
	)
}

func (u *UI) editorLine(gtx layout.Context, ed *widget.Editor, hint string) layout.Dimensions {
	ed.SingleLine = true
	return widget.Border{
		Color:        Surface2,
		CornerRadius: unit.Dp(8),
		Width:        unit.Dp(1),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		background(gtx, Surface0)
		return layout.UniformInset(unit.Dp(10)).Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			e := material.Editor(u.th(), ed, hint)
			e.Color = Text
			e.HintColor = Overlay1
			e.TextSize = unit.Sp(13.5)
			return e.Layout(gtx)
		})
	})
}

func background(gtx layout.Context, c color.NRGBA) {
	paint.FillShape(gtx.Ops, c, clip.Rect{Max: gtx.Constraints.Max}.Op())
}

// ---- helpers ----

func boolLabel(b bool, yes, no string) string {
	if b {
		return yes
	}
	return no
}

func boolColor(b bool) color.NRGBA {
	if b {
		return Green
	}
	return Peach
}

func statusListen(s StatusSnapshot) string {
	if s.Listen == "" {
		return "127.0.0.1:1080"
	}
	return s.Listen
}

func quotaLabel(r AccountRow) string {
	if r.QuotaLeft == "" {
		return "? / ?"
	}
	return r.QuotaLeft + " / " + r.QuotaMax
}

func hintFor(s StatusSnapshot) string {
	if !s.Running {
		return "Chưa kết nối: mở tab Vị trí và chọn một địa điểm, hoặc thêm account ở tab Account."
	}
	return "SOCKS5 proxy đang chạy — trỏ ứng dụng tới " + statusListen(s) + " để đi qua VPN. Rotator và token keeper tự chạy nền."
}

// EmailOr returns the snapshot email or fallback.
func (s StatusSnapshot) EmailOr(f string) string {
	if s.Email == "" {
		return f
	}
	return s.Email
}

// ServerOr returns the server host or fallback.
func (s StatusSnapshot) ServerOr(f string) string {
	if s.Server == "" {
		return f
	}
	return s.Server
}

// LocationOr returns "Country — City".
func (s StatusSnapshot) LocationOr(f string) string {
	if s.Country == "" {
		return f
	}
	return s.Country + " — " + s.City
}

// LastErrorOr returns the last engine error or fallback.
func (s StatusSnapshot) LastErrorOr(f string) string {
	if s.LastError == "" {
		return f
	}
	return s.LastError
}
