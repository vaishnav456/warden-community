package main

// remote_helper.go — interactive-session remote desktop helper.
//
// Go port of remote_helper.py. Launched by startRemoteRelay() (running as
// SYSTEM) into the currently logged-in user's desktop session via
// launchInteractiveHelper(), because SYSTEM's own session (session 0) has no
// real desktop to capture screen content from or send input into.
//
// This process does only screen capture, SendInput, and clipboard access —
// it never touches the network. All communication with the SYSTEM-side relay
// goes through two local named pipes (see remote_pipe.go):
//   - out pipe: this process writes frames/clipboard updates, service reads
//   - in pipe:  service writes input events, this process reads and dispatches
//
// Invoked as:
//
//	warden-agent.exe --remote-helper <out_pipe_name> <in_pipe_name>
//
// Exits when either pipe is closed (the SYSTEM side ends the session) or on
// unhandled error. Normally it inherits the interactive user's token. Before
// sign-in, when no such token exists, it runs as LocalSystem in the console
// session on winsta0\Winlogon so the login screen remains supportable.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func foregroundExplorerFolder() string {
	hwnd, _, _ := procGetForegroundWindow.Call()
	if hwnd == 0 {
		return ""
	}
	// Shell.Application exposes open shell windows and their documents. Do not
	// filter on Window.FullName: Windows 11's tabbed Explorer can expose an
	// empty/nonstandard FullName even though Document.Folder is valid. That
	// filter caused every window to be discarded on the live endpoint.
	// Prefer the foreground HWND, then fall back to the newest enumerated local
	// filesystem window. LocationURL covers shell frames where Folder.Self.Path
	// is temporarily empty during tab navigation.
	script := fmt.Sprintf(
		`$s=New-Object -ComObject Shell.Application;`+
			`$all=@($s.Windows()|ForEach-Object {`+
			`try{$p=$_.Document.Folder.Self.Path}catch{$p=''};`+
			`if(-not $p -and $_.LocationURL -like 'file:*'){`+
			`try{$p=([uri]$_.LocationURL).LocalPath}catch{$p=''}};`+
			`if($p -match '^(?i)C:\\Users\\'){[pscustomobject]@{H=[int64]$_.HWND;P=$p}}`+
			`});`+
			`$w=$all|Where-Object {$_.H -eq %d}|Select-Object -First 1;`+
			`if(-not $w){$w=$all|Select-Object -Last 1};`+
			`if($w){$w.P}`,
		hwnd,
	)
	cmd := exec.Command(
		"powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script,
	)
	// This helper runs in the interactive user's desktop. Without explicit
	// hidden-process flags, every destination lookup flashes a PowerShell
	// console over the remote user's screen.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: 0x08000000, // CREATE_NO_WINDOW
	}
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func connectPipeClient(pipeName string, access uint32, retries int, delay time.Duration) (windows.Handle, error) {
	namePtr, err := windows.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0, err
	}
	var lastErr error
	for i := 0; i < retries; i++ {
		h, err := windows.CreateFile(
			namePtr, access, 0, nil, windows.OPEN_EXISTING, 0, 0,
		)
		if err == nil {
			return h, nil
		}
		lastErr = err
		time.Sleep(delay)
	}
	return 0, fmt.Errorf("could not connect to %s: %w", pipeName, lastErr)
}

func runRemoteHelper(outPipeName, inPipeName string) int {
	outHandle, err := connectPipeClient(outPipeName, windows.GENERIC_WRITE, 20, 250*time.Millisecond)
	if err != nil {
		logError("remote helper: %v", err)
		return 1
	}

	inHandle, err := connectPipeClient(inPipeName, windows.GENERIC_READ, 20, 250*time.Millisecond)
	if err != nil {
		windows.CloseHandle(outHandle)
		logError("remote helper: %v", err)
		return 1
	}

	outFile := pipeFile{outHandle}
	inFile := pipeFile{inHandle}

	var writeMu sync.Mutex
	writeMsg := func(tag byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return writePipeMsg(outFile, tag, payload)
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	// Force-unblock any pending ReadFile/WriteFile call running in the other
	// goroutines — those synchronous Win32 calls have no cancellation token
	// of their own, so closing the handle they are blocked on is the only
	// way to make them return.
	requestStop := func() {
		stopOnce.Do(func() {
			close(stop)
			windows.CloseHandle(outHandle)
			windows.CloseHandle(inHandle)
		})
	}
	defer requestStop()

	setDPIAware()
	releaseModifierKeys()
	defer releaseModifierKeys()
	monitors := displayMonitors()
	selectedMonitor := 0
	var monitorMu sync.RWMutex
	currentMonitor := func() monitorRect {
		monitorMu.RLock()
		defer monitorMu.RUnlock()
		return monitors[selectedMonitor]
	}
	// Encode resolution the browser has asked for (0 = no preference, use
	// native). Updated by a "viewport_size" input event — see the input loop
	// below — so a browser displaying the stream smaller than native
	// resolution doesn't pay full-resolution encode/transfer cost for
	// detail nobody can see; drawImage() on the browser side scales
	// whatever size arrives back up to fill the canvas regardless.
	var sizeMu sync.Mutex
	requestedW, requestedH := 0, 0
	targetSize := func(nativeW, nativeH int) (int, int) {
		sizeMu.Lock()
		rw, rh := requestedW, requestedH
		sizeMu.Unlock()
		if rw <= 0 || rh <= 0 || rw >= nativeW || rh >= nativeH {
			return nativeW, nativeH
		}
		scale := float64(rw) / float64(nativeW)
		if s := float64(rh) / float64(nativeH); s < scale {
			scale = s
		}
		w := int(float64(nativeW) * scale)
		h := int(float64(nativeH) * scale)
		if w < 1 {
			w = 1
		}
		if h < 1 {
			h = 1
		}
		return w, h
	}
	sw, sh := monitors[0].width(), monitors[0].height()
	if err := writeMsg('S', []byte(fmt.Sprintf("%dx%d", sw, sh))); err != nil {
		logError("remote helper: screen-size handshake failed: %v", err)
		return 1
	}
	monitorPayload := make([]map[string]interface{}, 0, len(monitors))
	for index, monitor := range monitors {
		monitorPayload = append(monitorPayload, map[string]interface{}{
			"id": index, "name": fmt.Sprintf("Display %d", index+1),
			"x": monitor.Left, "y": monitor.Top,
			"w": monitor.width(), "h": monitor.height(),
		})
	}
	if encoded, err := json.Marshal(monitorPayload); err == nil {
		_ = writeMsg('M', encoded)
	}

	var wg sync.WaitGroup

	// Capture loop. Prefers Desktop Duplication (DXGI) for the primary
	// monitor when available — real-hardware GPU composition means plain GDI
	// BitBlt (used below as a fallback) frequently can't see the actual
	// composited frame at all (see dxgi_capture.go's doc comment). Desktop
	// Duplication is also documented to simply not work on the secure
	// (Winlogon) desktop, which newDXGICapturer naturally fails on, falling
	// back to GDI there exactly as before this helper gained DXGI support.
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Desktop attachment and GDI batching are OS-thread state.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var lastCaptureErrLog time.Time
		var captureFailedSince time.Time
		var captureState remoteCaptureState
		var dxgi *dxgiCapturer
		helperDesktop, _ := currentDesktopName()
		// Desktop Duplication is documented by Microsoft to not work on the
		// secure desktop — confirmed live: it can report itself as "active"
		// there yet only ever produce black frames, unlike the GDI BitBlt
		// path (fixed separately), which does work there. Skip attempting it
		// entirely rather than let it silently win over a working fallback.
		if desktopName, err := currentDesktopName(); err == nil && strings.EqualFold(desktopName, "winlogon") {
			_ = writeMsg('L', []byte("on secure desktop; DXGI capture skipped, using GDI"))
		} else {
			// Retries: DuplicateOutput can transiently fail right after a
			// sign-out/sign-in cycle while the OS finishes releasing the
			// previous (abruptly-killed) helper's duplication lock on this
			// output — see newDXGICapturerRetrying's doc comment.
			var dxgiErr error
			dxgi, dxgiErr = newDXGICapturerRetrying(0, 6, 500*time.Millisecond)
			if dxgiErr != nil {
				_ = writeMsg('L', []byte(fmt.Sprintf("DXGI capture unavailable, using GDI: %v", dxgiErr)))
				dxgi = nil
			} else {
				_ = writeMsg('L', []byte("DXGI capture active for primary monitor"))
			}
		}
		defer func() {
			if dxgi != nil {
				dxgi.close()
			}
		}()

		lastSelectedMonitor := -1

		for {
			select {
			case <-stop:
				return
			default:
			}

			// Secure-attention screens switch the input desktop without a
			// WTS_SESSION_LOCK event. Detect that boundary directly before a
			// stale DXGI/GDI handle can emit black transition frames.
			inputDesktop, inputErr := inputDesktopName()
			inputMoved := desktopNamesDiffer(helperDesktop, inputDesktop)
			if errors.Is(inputErr, windows.ERROR_ACCESS_DENIED) && strings.EqualFold(helperDesktop, "default") {
				// A normal user cannot open Winlogon's secure input desktop. The
				// access denial is itself the expected boundary signal.
				inputMoved = true
			}
			if inputMoved {
				_ = writeMsg('L', []byte(fmt.Sprintf("input desktop moved from %s to %s; switching helper", helperDesktop, inputDesktop)))
				_ = writeMsg('X', nil)
				requestStop()
				return
			}

			monitorMu.RLock()
			selectedIndex := selectedMonitor
			region := monitors[selectedMonitor]
			monitorMu.RUnlock()
			if selectedIndex != lastSelectedMonitor {
				// The browser canvas now represents a different monitor. A DXGI
				// dirty rectangle is meaningful only on top of a full frame from
				// that same output, so force a new baseline when switching back.
				captureState.reset()
				lastSelectedMonitor = selectedIndex
			}
			// EnumDisplayMonitors and DXGI EnumOutputs do not promise the same
			// ordering. Only use this duplication object when its actual desktop
			// bounds match the selected monitor; otherwise a multi-monitor machine
			// can display one screen while sending input to another.
			dxgiMatchesSelection := dxgi != nil &&
				dxgi.left == region.Left && dxgi.top == region.Top &&
				dxgi.width == region.width() && dxgi.height == region.height()

			sent := false
			useGDI := true

			if dxgiMatchesSelection {
				buf, w, h, dirty, dErr := dxgi.grabBGRA()
				if dErr == errNoNewFrame && len(captureState.pixels) > 0 {
					ew, eh := targetSize(captureState.width, captureState.height)
					if !captureState.shouldReplay(time.Now(), ew, eh) {
						time.Sleep(30 * time.Millisecond)
						continue
					}
					// Replay the latest complete DXGI snapshot, including every
					// intervening delta. GDI can see a different/incomplete image
					// and must not replace a healthy DXGI baseline during idle.
					buf, w, h = captureState.pixels, captureState.width, captureState.height
					dirty, dErr = nil, nil
				}
				switch dErr {
				case errNoNewFrame:
					// Only bootstrap with GDI before DXGI has supplied a frame.
					// Once sent, keep that bootstrap image until DXGI is ready.
					if !captureState.needsBootstrap() {
						time.Sleep(30 * time.Millisecond)
						continue
					}
				case errAccessLost:
					dxgi.close()
					dxgi, dErr = newDXGICapturerRetrying(0, 6, 500*time.Millisecond)
					if dErr != nil {
						_ = writeMsg('L', []byte(fmt.Sprintf("DXGI capture lost, could not reinit, using GDI: %v", dErr)))
						dxgi = nil
					}
					captureState.reset()
					time.Sleep(30 * time.Millisecond)
					continue
				case nil:
					useGDI = false
					captureState.remember(buf, w, h)
					ew, eh := targetSize(w, h)
					ux, uy, uw, uh, haveDirty := unionDirtyRects(dirty, w, h)
					// Always send a full frame the first time this DXGI
					// session captures anything (there's no prior canvas
					// content yet for a partial update to patch), and
					// whenever the changed region covers most of the screen
					// anyway (cheaper than a large partial update, and
					// simpler than reasoning about several dirty rects).
					// A periodic full frame bounds recovery time if a browser
					// deliberately drops queued deltas under decode pressure.
					// Without this, one missing partial update corrupts that
					// region indefinitely on a continuously changing desktop.
					sendFull := captureState.needsFull(time.Now(), haveDirty, uw*uh, w*h, ew, eh)
					if sendFull {
						encBuf := downscaleBGRA(buf, w, h, ew, eh)
						frame, encErr := encodeBGRAJPEG(encBuf, ew, eh, 60)
						if encErr != nil {
							_ = writeMsg('L', []byte(fmt.Sprintf("DXGI frame encode failed, using GDI: %v", encErr)))
							useGDI = true
							break
						}
						if err := writeMsg('F', frame); err != nil {
							requestStop()
							return
						}
						captureState.sentFull(time.Now(), ew, eh)
						sent = true
					} else {
						if uw <= 0 || uh <= 0 {
							// Shouldn't happen given unionDirtyRects' contract
							// (ok=true guarantees positive dimensions), but
							// never risk a sleepless busy-loop over it.
							useGDI = true
							break
						}
						// Reuse the SAME scale factor computed for the whole
						// screen (ew/w, eh/h) rather than deriving one from
						// just this crop's own (usually much smaller)
						// dimensions — targetSize() compares its argument
						// against the browser's requested FULL-screen size,
						// which isn't meaningful applied to a small sub-rect.
						crop := cropBGRA(buf, w, ux, uy, uw, uh)
						cew, ceh := uw, uh
						if ew != w || eh != h {
							cew = int(float64(uw) * float64(ew) / float64(w))
							ceh = int(float64(uh) * float64(eh) / float64(h))
							if cew < 1 {
								cew = 1
							}
							if ceh < 1 {
								ceh = 1
							}
						}
						encBuf := downscaleBGRA(crop, uw, uh, cew, ceh)
						frame, encErr := encodeBGRAJPEG(encBuf, cew, ceh, 60)
						if encErr != nil {
							_ = writeMsg('L', []byte(fmt.Sprintf("DXGI partial-frame encode failed, using GDI: %v", encErr)))
							useGDI = true
							break
						}
						if err := writeMsg('P', buildPartialFramePayload(ux, uy, uw, uh, frame)); err != nil {
							requestStop()
							return
						}
						sent = true
					}
				default:
					_ = writeMsg('L', []byte(fmt.Sprintf("DXGI capture failed, using GDI this frame: %v", dErr)))
				}
			}

			if useGDI {
				// A consumed DXGI frame may have failed before transmission.
				// Even if GDI also fails, the next delta cannot assume the
				// browser received those changes; require a fresh full image.
				captureState.invalidateBaseline()
				frame, _, _, gdiErr := grabJPEGRegion(60, region)
				if gdiErr != nil {
					// Previously swallowed entirely: a persistent capture
					// failure (e.g. BitBlt/GetDIBits erroring on this
					// desktop/driver) sent zero 'F' frames forever with
					// nothing explaining why. logWarn() alone doesn't reach
					// agent.log from here: this process normally runs as the
					// interactive user (not SYSTEM), and dataDir is
					// deliberately ACL'd SYSTEM-only (see hardenDataDir() in
					// tamper.go) — writing this process's own log file would
					// fail silently. Send it over the pipe instead so the
					// SYSTEM-side relay (which does have a working logger)
					// writes it on our behalf. Rate-limited: this loop
					// retries every 100ms.
					if time.Since(lastCaptureErrLog) > 5*time.Second {
						_ = writeMsg('L', []byte(fmt.Sprintf("screen capture failed: %v", gdiErr)))
						lastCaptureErrLog = time.Now()
					}
					// During sign-in and sign-out Windows can announce the new
					// desktop before its graphics objects are usable. A helper
					// created in that narrow window keeps an invalid HDC forever;
					// retrying BitBlt in the same process never recovers. Exit after
					// a short continuous failure window so the SYSTEM relay launches
					// a fresh helper in the now-ready console session. This is based
					// on capture errors, not black pixels, so legitimate dark screens
					// never cause desktop thrashing or visible flicker.
					if captureFailedSince.IsZero() {
						captureFailedSince = time.Now()
					} else if time.Since(captureFailedSince) >= 3*time.Second {
						_ = writeMsg('L', []byte("capture remained unavailable; restarting helper on the current desktop"))
						requestStop()
						return
					}
					time.Sleep(100 * time.Millisecond)
					continue
				}
				captureFailedSince = time.Time{}
				if err := writeMsg('F', frame); err != nil {
					requestStop()
					return
				}
				captureState.sentGDI(time.Now())
				sent = true
			}

			if sent && !useGDI {
				captureState.sentPartial(time.Now())
			}
			if useGDI {
				// Only needed for the GDI polling path, which would otherwise
				// busy-loop pegging a CPU core. DXGI's AcquireNextFrame is
				// already event-driven — it blocks until an actual screen
				// change happens — so adding a fixed sleep on top of that
				// only inflates every frame's latency for no benefit.
				time.Sleep(50 * time.Millisecond) // ~20 fps cap for GDI
			}
		}
	}()

	// Clipboard loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		last := ""
		for {
			select {
			case <-stop:
				return
			default:
			}
			current := clipboardGet()
			if current != "" && current != last {
				last = current
				if err := writeMsg('C', []byte(current)); err != nil {
					requestStop()
					return
				}
			}
			select {
			case <-stop:
				return
			case <-time.After(time.Second):
			}
		}
	}()

	// Input loop — reads from the pipe (blocking); closing inHandle from
	// requestStop() elsewhere unblocks this read.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer requestStop()
		for {
			tag, payload, err := readPipeMsg(inFile)
			if err != nil {
				return
			}
			if tag == 'I' {
				var evt map[string]interface{}
				if json.Unmarshal(payload, &evt) == nil {
					if eventType, _ := evt["type"].(string); eventType == "drop_target_request" {
						_ = writeMsg('D', []byte(foregroundExplorerFolder()))
					} else if eventType == "clipboard_read" {
						// Used by drag-and-drop after the viewer copies
						// Explorer's address bar. Reply even when the value
						// has not changed, unlike the periodic clipboard loop.
						_ = writeMsg('C', []byte(clipboardGet()))
					} else if eventType == "viewport_size" {
						wFloat, wOK := evt["w"].(float64)
						hFloat, hOK := evt["h"].(float64)
						if wOK && hOK {
							sizeMu.Lock()
							requestedW, requestedH = int(wFloat), int(hFloat)
							sizeMu.Unlock()
						}
					} else if eventType == "monitor_select" {
						indexFloat, ok := evt["id"].(float64)
						index := int(indexFloat)
						if ok && index >= 0 && index < len(monitors) {
							monitorMu.Lock()
							selectedMonitor = index
							monitorMu.Unlock()
							selected := monitors[index]
							_ = writeMsg('S', []byte(fmt.Sprintf("%dx%d", selected.width(), selected.height())))
						}
					} else {
						dispatchInput(evt, currentMonitor())
					}
				}
			}
		}
	}()

	<-stop
	wg.Wait()
	return 0
}
