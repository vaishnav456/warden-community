package main

import (
	"fmt"
	"io"
	"log"
	"os"
)

var logger *log.Logger

const (
	maxLogBytes = 10 * 1024 * 1024
	logBackups  = 3
)

type rotatingLogWriter struct {
	path string
	file *os.File
	size int64
}

func newRotatingLogWriter(path string) (*rotatingLogWriter, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	return &rotatingLogWriter{path: path, file: f, size: info.Size()}, nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	if w.size+int64(len(p)) > maxLogBytes {
		if err := w.rotate(); err != nil {
			return 0, err
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingLogWriter) rotate() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	_ = os.Remove(fmt.Sprintf("%s.%d", w.path, logBackups))
	for i := logBackups - 1; i >= 1; i-- {
		_ = os.Rename(
			fmt.Sprintf("%s.%d", w.path, i),
			fmt.Sprintf("%s.%d", w.path, i+1),
		)
	}
	if err := os.Rename(w.path, w.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	w.file = f
	w.size = 0
	return nil
}

func initLogging() {
	flags := log.Ldate | log.Ltime
	f, err := newRotatingLogWriter(logPath)
	if err != nil {
		logger = log.New(os.Stderr, "", flags)
		return
	}
	// Write to both log file and stderr (service manager captures stderr)
	logger = log.New(io.MultiWriter(f, os.Stderr), "", flags)
}

func logInfo(format string, args ...interface{}) {
	if logger != nil {
		logger.Printf("INFO  "+format, args...)
	} else {
		fmt.Fprintf(os.Stderr, "INFO  "+format+"\n", args...)
	}
}

func logWarn(format string, args ...interface{}) {
	if logger != nil {
		logger.Printf("WARN  "+format, args...)
	} else {
		fmt.Fprintf(os.Stderr, "WARN  "+format+"\n", args...)
	}
}

func logError(format string, args ...interface{}) {
	if logger != nil {
		logger.Printf("ERROR "+format, args...)
	} else {
		fmt.Fprintf(os.Stderr, "ERROR "+format+"\n", args...)
	}
}
