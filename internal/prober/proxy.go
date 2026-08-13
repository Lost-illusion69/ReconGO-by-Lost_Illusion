package prober

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

func socks5Dialer(u *url.URL) (proxyDialer, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		host = net.JoinHostPort(host, "1080")
	}
	return &socks5DialerImpl{
		proxyAddr: host,
		username:  u.User.Username(),
		password: func() string {
			p, _ := u.User.Password()
			return p
		}(),
	}, nil
}

type proxyDialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// socks5DialerImpl implements a minimal SOCKS5 CONNECT handshake (no external deps).
type socks5DialerImpl struct {
	proxyAddr string
	username  string
	password  string
}

func (d *socks5DialerImpl) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("prober: socks5 unsupported network %q", network)
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", d.proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("prober: socks5 dial proxy: %w", err)
	}

	if err := d.handshake(conn, addr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (d *socks5DialerImpl) handshake(conn net.Conn, target string) error {
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return fmt.Errorf("prober: socks5 target: %w", err)
	}

	// Method selection: no auth or username/password.
	methods := []byte{0x05, 0x01, 0x00}
	if d.username != "" {
		methods = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := conn.Write(methods); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := ioReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("prober: socks5 bad version")
	}

	switch resp[1] {
	case 0x00:
		// no auth
	case 0x02:
		if err := d.auth(conn); err != nil {
			return err
		}
	default:
		return fmt.Errorf("prober: socks5 unsupported auth method %d", resp[1])
	}

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	p := make([]byte, 2)
	p[0] = byte((portInt(port) >> 8) & 0xff)
	p[1] = byte(portInt(port) & 0xff)
	req = append(req, p...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	reply := make([]byte, 4)
	if _, err := ioReadFull(conn, reply); err != nil {
		return err
	}
	if reply[1] != 0x00 {
		return fmt.Errorf("prober: socks5 connect failed code %d", reply[1])
	}

	// Consume bind address.
	switch reply[3] {
	case 0x01:
		_, err = ioReadFull(conn, make([]byte, 4+2))
	case 0x03:
		l := make([]byte, 1)
		if _, err = ioReadFull(conn, l); err == nil {
			_, err = ioReadFull(conn, make([]byte, int(l[0])+2))
		}
	case 0x04:
		_, err = ioReadFull(conn, make([]byte, 16+2))
	}
	return err
}

func (d *socks5DialerImpl) auth(conn net.Conn) error {
	u := []byte(d.username)
	p := []byte(d.password)
	buf := make([]byte, 0, 3+len(u)+len(p))
	buf = append(buf, 0x01, byte(len(u)))
	buf = append(buf, u...)
	buf = append(buf, byte(len(p)))
	buf = append(buf, p...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := ioReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("prober: socks5 auth failed")
	}
	return nil
}

func ioReadFull(conn net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		got, err := conn.Read(b[n:])
		n += got
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

func portInt(port string) int {
	var p int
	for i := 0; i < len(port); i++ {
		p = p*10 + int(port[i]-'0')
	}
	if p == 0 {
		return 80
	}
	return p
}
