package mail

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeSMTP is a minimal SMTP server for the sender's dial/fallback tests. It
// counts sessions and delivered messages. greeting is the banner it sends, and
// rejectRcpt makes it refuse every RCPT TO.
type fakeSMTP struct {
	addr       string
	greeting   string
	rejectRcpt bool
	sessions   atomic.Int32
	delivered  atomic.Int32
}

func newFakeSMTP(t *testing.T, greeting string, rejectRcpt bool) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fakeSMTP{addr: ln.Addr().String(), greeting: greeting, rejectRcpt: rejectRcpt}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	f.sessions.Add(1)
	r := bufio.NewReader(c)
	io.WriteString(c, f.greeting+"\r\n")
	if !strings.HasPrefix(f.greeting, "220") {
		return
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			io.WriteString(c, "250 fake\r\n")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			io.WriteString(c, "250 ok\r\n")
		case strings.HasPrefix(cmd, "RCPT TO"):
			if f.rejectRcpt {
				io.WriteString(c, "554 relay access denied\r\n")
			} else {
				io.WriteString(c, "250 ok\r\n")
			}
		case cmd == "DATA":
			io.WriteString(c, "354 go ahead\r\n")
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
			}
			f.delivered.Add(1)
			io.WriteString(c, "250 queued\r\n")
		case cmd == "QUIT":
			io.WriteString(c, "221 bye\r\n")
			return
		default:
			io.WriteString(c, "250 ok\r\n")
		}
	}
}

// closedAddr returns a loopback address with nothing listening on it.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func testSender(primary, fallback string) *Sender {
	s := NewSender(primary, "api.test", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if fallback != "" {
		s.WithFallback(fallback)
	}
	return s
}

func testMessage() *Message {
	return &Message{
		From:     Address{Email: "from@example.com"},
		To:       []Address{{Email: "to@example.com"}},
		Subject:  "hi",
		TextBody: "hello",
	}
}

func TestSend_UsesPrimaryWhenUp(t *testing.T) {
	primary := newFakeSMTP(t, "220 primary", false)
	fallback := newFakeSMTP(t, "220 fallback", false)
	if _, err := testSender(primary.addr, fallback.addr).Send(testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if primary.delivered.Load() != 1 {
		t.Errorf("primary delivered %d, want 1", primary.delivered.Load())
	}
	if fallback.sessions.Load() != 0 {
		t.Errorf("fallback contacted %d times while the primary was up, want 0", fallback.sessions.Load())
	}
}

// The case #227 needs it for: the api is up before Postfix has the new listener.
func TestSend_FallsBackWhenPrimaryRefuses(t *testing.T) {
	fallback := newFakeSMTP(t, "220 fallback", false)
	if _, err := testSender(closedAddr(t), fallback.addr).Send(testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if fallback.delivered.Load() != 1 {
		t.Errorf("fallback delivered %d, want 1", fallback.delivered.Load())
	}
}

// A primary that answers but won't greet has accepted nothing, so falling back
// is still safe.
func TestSend_FallsBackWhenPrimaryWontGreet(t *testing.T) {
	primary := newFakeSMTP(t, "554 not now", false)
	fallback := newFakeSMTP(t, "220 fallback", false)
	if _, err := testSender(primary.addr, fallback.addr).Send(testMessage()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if fallback.delivered.Load() != 1 {
		t.Errorf("fallback delivered %d, want 1", fallback.delivered.Load())
	}
}

// Once the primary has greeted, a later failure must NOT fall back: the session
// may have got far enough to queue the message, and a retry could send it twice.
func TestSend_NoFallbackAfterPrimaryGreets(t *testing.T) {
	primary := newFakeSMTP(t, "220 primary", true)
	fallback := newFakeSMTP(t, "220 fallback", false)
	_, err := testSender(primary.addr, fallback.addr).Send(testMessage())
	if err == nil || !strings.Contains(err.Error(), "smtp rcpt") {
		t.Fatalf("Send = %v, want the primary's RCPT error", err)
	}
	if fallback.sessions.Load() != 0 {
		t.Errorf("fallback contacted %d times after the primary greeted, want 0", fallback.sessions.Load())
	}
}

func TestSend_BothDownReportsBoth(t *testing.T) {
	primary, fallback := closedAddr(t), closedAddr(t)
	_, err := testSender(primary, fallback).Send(testMessage())
	if err == nil {
		t.Fatal("Send succeeded with nothing listening")
	}
	if !strings.Contains(err.Error(), primary) || !strings.Contains(err.Error(), "fallback "+fallback) {
		t.Errorf("error %q should name both the primary and the fallback", err)
	}
}

// Without a fallback the sender behaves as it always did.
func TestSend_NoFallbackConfigured(t *testing.T) {
	if _, err := testSender(closedAddr(t), "").Send(testMessage()); err == nil {
		t.Fatal("Send succeeded with nothing listening and no fallback")
	}
}
