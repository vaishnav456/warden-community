package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type homeNoticeState struct {
	status string
	at     time.Time
}

var homeNotices = struct {
	sync.Mutex
	users map[string]homeNoticeState
}{users: make(map[string]homeNoticeState)}

// No file paths, credentials or node addresses appear in user notifications.
func homeSyncNotice(report homeSyncReport) (title, message, severity string) {
	if report.Status != "completed" || report.Failed > 0 || report.Skipped > 0 {
		return "Warden Home sync needs attention", fmt.Sprintf("Sync did not fully complete. %d uploaded, %d downloaded, %d failed, %d skipped. Check the Warden sync job details before assuming your files are backed up.", report.Uploaded, report.Downloaded, report.Failed, report.Skipped), "warning"
	}
	return "Warden Home sync complete", fmt.Sprintf("Incremental sync finished: %d uploaded, %d downloaded, %d unchanged. Only new or changed files were transferred.", report.Uploaded, report.Downloaded, report.Unchanged), "info"
}

func shouldShowHomeNotice(report homeSyncReport, previous homeNoticeState, now time.Time) bool {
	if previous.at.IsZero() || previous.status != report.Status {
		return true
	}
	// Repeated failures are rate-limited; successful idle polls remain silent.
	if report.Status != "completed" {
		return now.Sub(previous.at) >= 15*time.Minute
	}
	return report.Uploaded+report.Downloaded > 0 && now.Sub(previous.at) >= time.Minute
}

func notifyHomeSyncResult(report homeSyncReport) {
	if report.Username == "" {
		return
	}
	// Normalize partial reports so they can never generate a success notice.
	if report.Failed+report.Skipped > 0 {
		report.Status = "failed"
	}
	key := strings.ToLower(report.Username)
	homeNotices.Lock()
	defer homeNotices.Unlock()
	now := time.Now()
	if !shouldShowHomeNotice(report, homeNotices.users[key], now) {
		return
	}
	// This check prevents another user from receiving a previous user's result.
	token, err := activeUserPrimaryToken(report.Username)
	if err != nil {
		return
	} // No interactive session: job reporting still works.
	exe, err := os.Executable()
	if err != nil {
		token.Close()
		return
	}
	title, message, severity := homeSyncNotice(report)
	helper, err := createInteractiveProcess(token, `winsta0\default`, exe, []string{"--user-notification", title, message, severity})
	if err != nil {
		logWarn("Could not display Warden Home sync result: %v", err)
		return
	}
	homeNotices.users[key] = homeNoticeState{status: report.Status, at: now}
	go func() {
		if _, finished := helper.wait(20 * time.Second); !finished {
			helper.terminate(2 * time.Second)
		}
	}()
}
