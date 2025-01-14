package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"

	"github.com/cloudflare/cfssl/csr"
	"github.com/cloudflare/cfssl/initca"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReproduceTLSHang(t *testing.T) {
	req := csr.CertificateRequest{
		CN:         "my-central.example.org",
		KeyRequest: csr.NewKeyRequest(),
	}
	caCert, _, caKey, err := initca.New(&req)
	require.NoError(t, err)
	defaultCert, err := tls.X509KeyPair(caCert, caKey)
	require.NoError(t, err)

	lis, dialContext := NewPipeListener()

	server := tls.NewListener(lis, &tls.Config{
		GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			return &tls.Config{
				Certificates: []tls.Certificate{
					defaultCert,
				},
			}, nil
		},
		NextProtos: []string{"h2"},
		ClientAuth: tls.VerifyClientCertIfGiven,
		MinVersion: tls.VersionTLS12,
	})

	serverErrC := make(chan error, 1)
	serverCtx, cancelServerCtx := context.WithCancel(context.Background())
	go func() {
		defer cancelServerCtx() // make sure dials/handshakes don't block if the server exits prematurely
		conn, err := server.Accept()
		for ; err == nil; conn, err = server.Accept() {
			_ = conn.(*tls.Conn).HandshakeContext(serverCtx) // client takes care of error checking
			go func(c net.Conn) { _ = c.Close() }(conn)      // Close might block due to a grace period
		}
		serverErrC <- err
	}()

	serverName := "not-central.stackrox.svc"

	conn, err := dialContext(serverCtx)
	require.NoError(t, err)

	tlsConn := tls.Client(conn, &tls.Config{
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("remote peer presented no certificates")
			}

			certs := make([]*x509.Certificate, 0, len(rawCerts))
			for _, rawCert := range rawCerts {
				cert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return errors.Wrap(err, "failed to parse peer certificate")
				}
				certs = append(certs, cert)
			}
			return x509.HostnameError{Host: serverName, Certificate: certs[0]}
		},
		NextProtos:         []string{"h2", "http/1.1"},
		ServerName:         serverName,
		ClientAuth:         tls.NoClientCert,
		InsecureSkipVerify: true,
	})
	require.ErrorAs(t, tlsConn.HandshakeContext(serverCtx), &x509.HostnameError{})
	go func(c net.Conn) { _ = c.Close() }(conn) // Close might block due to a grace period

	require.NoError(t, server.Close())
	err = <-serverErrC
	assert.ErrorIs(t, err, ErrClosed)
}

const (
	// Network is the network reported by a pipe's address.
	Network = "pipe"
)

var (
	// ErrClosed indicates that a call to Accept() failed because the listener was closed
	ErrClosed = errors.New("listener was closed")

	// ErrAlreadyClosed indicates that a call to Close() failed because the listener had already been closed.
	ErrAlreadyClosed = errors.New("already closed")

	pipeAddr = func() net.Addr {
		c1, c2 := net.Pipe()
		addr := c1.RemoteAddr()
		_ = c1.Close()
		_ = c2.Close()
		return addr
	}()
)

// DialContextFunc is a function for dialing a pipe listener.
type DialContextFunc func(context.Context) (net.Conn, error)

type pipeListener struct {
	closed       Signal
	serverConnsC chan net.Conn
}

// NewPipeListener returns a net.Listener that accepts connections which are local pipe connections (i.e., via
// net.Pipe()). It also returns a function that implements a context-aware dial.
func NewPipeListener() (net.Listener, DialContextFunc) {
	lis := &pipeListener{
		closed:       NewSignal(),
		serverConnsC: make(chan net.Conn),
	}

	return lis, lis.DialContext
}

func (l *pipeListener) Accept() (net.Conn, error) {
	if l.closed.IsDone() {
		return nil, ErrClosed
	}
	select {
	case conn := <-l.serverConnsC:
		return conn, nil
	case <-l.closed.Done():
		return nil, ErrClosed
	}
}

func (l *pipeListener) DialContext(ctx context.Context) (net.Conn, error) {
	if l.closed.IsDone() {
		return nil, ErrClosed
	}

	serverConn, clientConn := net.Pipe()

	select {
	case l.serverConnsC <- serverConn:
		return clientConn, nil
	case <-l.closed.Done():
		return nil, ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *pipeListener) Addr() net.Addr {
	return pipeAddr
}

func (l *pipeListener) Close() error {
	if !l.closed.Signal() {
		return ErrAlreadyClosed
	}
	return nil
}

