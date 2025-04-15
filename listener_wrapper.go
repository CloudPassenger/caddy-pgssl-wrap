package wrapper

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

var (
	// PostgresStartTLSMsg is the message sent by PostgreSQL clients to initiate SSL
	// The message consists of a 4-byte length (8) followed by the SSL request code (80877103)
	PostgresStartTLSMsg = []byte{0, 0, 0, 8, 4, 210, 22, 47} // int32(8) + int32(80877103)

	// PostgresStartTLSReply is the single byte 'S' sent back to clients to indicate SSL is supported
	PostgresStartTLSReply = []byte{83} // 'S' byte
)

// ListenerWrapper provides PostgreSQL SSL support to Caddy by implementing
// the caddy.ListenerWrapper interface. It detects PostgreSQL's SSL handshake
// request and responds correctly to enable TLS for PostgreSQL connections.
type ListenerWrapper struct {
	// Timeout specifies how long to wait when peeking at connections
	Timeout caddy.Duration `json:"timeout,omitempty"`

	// Allow specifies which IPs are allowed to use this wrapper
	Allow []string `json:"allow,omitempty"`

	// Deny specifies which IPs are not allowed to use this wrapper
	Deny []string `json:"deny,omitempty"`

	Logger *zap.Logger
}

// Provision sets up the listener wrapper.
func (pp *ListenerWrapper) Provision(ctx caddy.Context) error {
	// If no timeout is specified, use a default of 3 seconds
	if pp.Timeout == 0 {
		pp.Timeout = caddy.Duration(300 * time.Millisecond)
	}

	pp.Logger = ctx.Logger(pp)

	return nil
}

// WrapListener adds PostgreSQL SSL support to the listener.
func (pp *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &pgListener{
		Listener: l,
		timeout:  time.Duration(pp.Timeout),
		allow:    pp.Allow,
		deny:     pp.Deny,
		logger:   pp.Logger,
	}
}

// pgListener is a net.Listener that detects PostgreSQL connections
// and handles the initial SSL handshake.
type pgListener struct {
	net.Listener
	timeout time.Duration
	allow   []string
	deny    []string
	logger  *zap.Logger
}

// Accept accepts and returns the next connection to the listener.
func (l *pgListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		l.logger.Error("Error accepting connection", zap.Error(err))
		return nil, err
	}

	// Check if the IP is in the deny list - return the original connection if denied
	// This allows other components to process the connection instead of rejecting
	if len(l.deny) > 0 {
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		for _, deny := range l.deny {
			if ip == deny {
				l.logger.Debug("denied connection by deny list", zap.String("ip", ip))
				return conn, nil // Return original connection instead of closing
			}
		}
	}

	// Check if the IP is in the allow list (if specified)
	// If allow list exists and IP is not in it, return original connection
	if len(l.allow) > 0 {
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		allowed := false
		for _, allow := range l.allow {
			if ip == allow {
				l.logger.Debug("allowed connection by allow list", zap.String("ip", ip))
				allowed = true
				break
			}
		}
		if !allowed {
			return conn, nil // Return original connection instead of closing
		}
	}

	// Set a timeout for peeking data
	if l.timeout > 0 {
		err = conn.SetReadDeadline(time.Now().Add(l.timeout))
		if err != nil {
			// On error setting deadline, return the original connection
			// to allow other wrappers to handle it potentially.
			l.logger.Error("Error setting read deadline", zap.Error(err))
			return conn, nil
		}
	}

	// Create a buffered reader to peek the header
	// Use a large enough buffer size to optimize memory usage
	br := bufio.NewReaderSize(conn, 4096)

	// Try to detect if this is a PostgreSQL SSL request
	isPg, peekErr := isPostgres(br)
	if peekErr != nil {
		l.logger.Error("Error detecting PostgreSQL SSL request", zap.Error(peekErr))
	}

	l.logger.Debug("Detected PostgreSQL SSL request", zap.Bool("isPg", isPg), zap.Error(err))

	// Reset the deadline immediately after peeking
	if l.timeout > 0 {
		_ = conn.SetReadDeadline(time.Time{})
	}

	// Regardless of whether it's PG or if there was a peek error,
	// wrap the connection with pgConn to ensure the buffered reader is used.
	// The isTLS flag will determine the behavior in pgConn.Read.
	// If peekErr is not nil (e.g., timeout), isPg will be false.
	return &pgConn{
		Conn:    conn,
		reader:  br,
		isPgTLS: isPg && peekErr == nil, // Only treat as TLS if detection succeeded
	}, nil
}

// isPostgres determines whether the buffer contains the Postgres STARTTLS message.
func isPostgres(br *bufio.Reader) (bool, error) {
	// Peek the exact number of bytes we need for the PostgreSQL SSL request
	peeked, err := br.Peek(len(PostgresStartTLSMsg))
	if err != nil {
		// Don't log EOF or timeout errors, they are expected in some cases
		// But return the error so Accept knows detection might have failed
		var opErr *net.OpError
		if errors.Is(err, io.EOF) || (errors.As(err, &opErr) && opErr.Timeout()) {
			return false, err
		}
		// Log other unexpected errors
		return false, err
	}

	// Check if the peeked bytes match the PostgreSQL SSL request
	return bytes.Equal(peeked, PostgresStartTLSMsg), nil
}

// pgConn is a net.Conn that handles PostgreSQL SSL negotiation
// or passes through data if not a PG TLS connection.
type pgConn struct {
	net.Conn
	reader  *bufio.Reader
	isPgTLS bool

	mu      sync.Mutex
	msgSent bool // Whether the SSL handshake has been completed
}

// Read reads data from the connection.
// If this is a PostgreSQL TLS connection, it handles the SSL request message first.
func (c *pgConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If it's not a PG TLS connection, just read directly from the buffered reader.
	if !c.isPgTLS {
		return c.reader.Read(b)
	}

	// If it is a PG TLS connection, but we've already handled the handshake.
	if c.msgSent {
		return c.reader.Read(b)
	}

	// --- Handle the initial PG TLS handshake ---

	// Consume the SSL request message from the buffer without allocating new memory
	// We know it's already in the buffer because we peeked it in Accept.
	_, err = c.reader.Discard(len(PostgresStartTLSMsg))
	if err != nil {
		return 0, err
	}

	// Send the reply ('S') indicating SSL is supported
	_, err = c.Conn.Write(PostgresStartTLSReply)
	if err != nil {
		return 0, err
	}

	// Mark handshake as completed
	c.msgSent = true

	// Continue reading the actual TLS handshake data from the connection
	return c.reader.Read(b)
}

// Write writes data to the connection.
func (c *pgConn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}
