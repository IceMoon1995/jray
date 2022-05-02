package proxy

import (
	"bytes"
	"io"
	"os"
	"strings"
	"sync"

	_log "github.com/sirupsen/logrus"
)

var NormalErrMsgs []string = []string{
	"read: connection reset by peer",
	"write: broken pipe",
	"i/o timeout",
	"net/http: TLS handshake timeout",
	"io: read/write on closed pipe",
	"connect: connection refused",
	"connect: connection reset by peer",
	"use of closed network connection",
}

// 仅打印预料之外的错误信息
func LogErr(log *_log.Entry, err error) (loged bool) {
	msg := err.Error()
	for _, str := range NormalErrMsgs {
		if strings.Contains(msg, str) {
			//log.Debug(err)
			return
		}
	}
	//log.Error(err)
	loged = true
	return
}

// 转发流量
// Read a => Write b
// Read b => Write a
func Transfer(log *_log.Entry, a, b io.ReadWriteCloser) {
	done := make(chan struct{})
	defer close(done)

	forward := func(dst io.WriteCloser, src io.Reader, ec chan<- error) {
		_, err := io.Copy(dst, src)

		dst.Close() // 当一端读结束时，结束另一端的写

		select {
		case <-done:
			return
		case ec <- err:
			return
		}
	}

	errChan := make(chan error)
	go forward(a, b, errChan)
	go forward(b, a, errChan)

	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			LogErr(log, err)
			return // 如果有错误，直接返回
		}
	}
}

// 尝试将 Reader 读取至 buffer 中
// 如果未达到 limit，则成功读取进入 buffer
// 否则 buffer 返回 nil，且返回新 Reader，状态为未读取前
func ReaderToBuffer(r io.Reader, limit int64) ([]byte, io.Reader, error) {
	buf := bytes.NewBuffer(make([]byte, 0))
	lr := io.LimitReader(r, limit)

	_, err := io.Copy(buf, lr)
	if err != nil {
		return nil, nil, err
	}

	// 达到上限
	if int64(buf.Len()) == limit {
		// 返回新的 Reader
		return nil, io.MultiReader(bytes.NewBuffer(buf.Bytes()), r), nil
	}

	// 返回 buffer
	return buf.Bytes(), nil, nil
}

// Wireshark 解析 https 设置
var tlsKeyLogWriter io.Writer
var tlsKeyLogOnce sync.Once

func GetTlsKeyLogWriter() io.Writer {
	tlsKeyLogOnce.Do(func() {
		logfile := os.Getenv("SSLKEYLOGFILE")
		if logfile == "" {
			return
		}

		writer, err := os.OpenFile(logfile, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.WithField("in", "GetTlsKeyLogWriter").Debug(err)
			return
		}

		tlsKeyLogWriter = writer
	})
	return tlsKeyLogWriter
}
