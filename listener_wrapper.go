package wrapper

import (
	"bufio"
	"bytes"
	"net"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
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
}

// Provision sets up the listener wrapper.
func (pp *ListenerWrapper) Provision(ctx caddy.Context) error {
	// If no timeout is specified, use a default of 3 seconds
	if pp.Timeout == 0 {
		pp.Timeout = caddy.Duration(3 * time.Second)
	}

	return nil
}

// WrapListener adds PostgreSQL SSL support to the listener.
func (pp *ListenerWrapper) WrapListener(l net.Listener) net.Listener {
	return &pgListener{
		Listener: l,
		timeout:  time.Duration(pp.Timeout),
		allow:    pp.Allow,
		deny:     pp.Deny,
	}
}

// pgListener is a net.Listener that detects PostgreSQL connections
// and handles the initial SSL handshake.
type pgListener struct {
	net.Listener
	timeout time.Duration
	allow   []string
	deny    []string
}

// Accept accepts and returns the next connection to the listener.
func (l *pgListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Check if the IP is in the deny list - return the original connection if denied
	// This allows other components to process the connection instead of rejecting
	if len(l.deny) > 0 {
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		for _, deny := range l.deny {
			if ip == deny {
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
			return conn, nil // Return original connection on error
		}
	}

	// Create a buffered reader to peek the header
	// Use a large enough buffer size to optimize memory usage
	br := bufio.NewReaderSize(conn, 4096)

	// Try to detect if this is a PostgreSQL SSL request
	isPg, err := isPostgres(br)

	// Reset the deadline immediately to prevent timeout issues
	if l.timeout > 0 {
		_ = conn.SetReadDeadline(time.Time{})
	}

	// If it's not a PostgreSQL connection or we had an error peeking,
	// return a buffered connection with the original reader content
	if !isPg || err != nil {
		// Return a buffered connection that preserves what we've read
		return &bufferedConn{
			Conn:   conn,
			reader: br,
		}, nil
	}

	// If it is a PostgreSQL connection, wrap it with our special handler
	return &pgConn{
		Conn:   conn,
		reader: br,
	}, nil
}

// isPostgres determines whether the buffer contains the Postgres STARTTLS message.
func isPostgres(br *bufio.Reader) (bool, error) {
	// Peek the exact number of bytes we need for the PostgreSQL SSL request
	peeked, err := br.Peek(len(PostgresStartTLSMsg))
	if err != nil {
		return false, err
	}

	// Check if the peeked bytes match the PostgreSQL SSL request
	return bytes.Equal(peeked, PostgresStartTLSMsg), nil
}

// bufferedConn is a basic wrapper around a connection with a buffered reader
// This is used for non-PostgreSQL connections to avoid losing data we've peeked
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

// Read reads data from the connection.
func (c *bufferedConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

// pgConn is a net.Conn that handles PostgreSQL SSL negotiation
type pgConn struct {
	net.Conn
	reader *bufio.Reader

	mu        sync.Mutex
	msgSent   bool // Whether we have consumed the SSL request message
	replySent bool // Whether we have sent the 'S' reply
}

// Read reads data from the connection.
// If this is a PostgreSQL TLS connection, it handles the SSL request message.
func (c *pgConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// If already processed the handshake, just read normally
	if c.msgSent {
		return c.reader.Read(b)
	}

	// Consume the SSL request message from the buffer without allocating new memory
	// We know it's already in the buffer because we peeked it
	_, err = c.reader.Discard(len(PostgresStartTLSMsg))
	if err != nil {
		return 0, err
	}

	// Mark message as sent
	c.msgSent = true

	// Send the reply indicating SSL is supported
	_, err = c.Conn.Write(PostgresStartTLSReply)
	if err != nil {
		return 0, err
	}
	c.replySent = true

	// Continue reading from the connection
	return c.reader.Read(b)
}

// Write writes data to the connection.
func (c *pgConn) Write(b []byte) (n int, err error) {
	return c.Conn.Write(b)
}
