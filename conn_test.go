package smb2

import (
	"context"
	"crypto/aes"
	"net"
	"testing"
	"time"

	"go.kvsh.ch/smb2/internal/crypto/cmac"
	"go.kvsh.ch/smb2/internal/erref"
	"go.kvsh.ch/smb2/internal/smb2"
	"github.com/stretchr/testify/require"
)

func TestSessionRecv(t *testing.T) {
	require := require.New(t)

	// helper sends one request through c and returns the result of s.recv.
	roundTrip := func(t *testing.T, c *conn, s *session) error {
		t.Helper()
		var req smb2.ReadRequest
		req.CreditCharge = 1
		rr, err := c.send(context.Background(), &req)
		require.NoError(err)
		_, err = s.recv(rr)
		return err
	}

	t.Run("AdoptsSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const serverSessionId uint64 = 0x1234
		go fakeServer(direct(serverConn), nil, serverSessionId)

		s := &session{conn: c, sessionId: 0}

		require.NoError(roundTrip(t, c, s))
		require.Equal(serverSessionId, s.sessionId)
	})

	t.Run("MatchingSessionId", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		const id uint64 = 0xCAFE
		go fakeServer(direct(serverConn), nil, id)

		s := &session{conn: c, sessionId: id}

		require.NoError(roundTrip(t, c, s))
		require.Equal(id, s.sessionId)
	})

	t.Run("RejectsSessionIdMismatch", func(t *testing.T) {
		clientConn, serverConn := net.Pipe()
		c, cleanup := newBenchConn(clientConn)
		defer cleanup()

		go fakeServer(direct(serverConn), nil, 0xBBBB)

		s := &session{conn: c, sessionId: 0xAAAA}

		err := roundTrip(t, c, s)
		require.Error(err)
		require.IsType(&InvalidResponseError{}, err)
	})
}

func TestTryVerify(t *testing.T) {
	// builds an SMB2 response header
	makeHdr := func(status uint32, flags uint32, sessionId, msgID uint64) smb2.PacketCodec {
		pkt := make([]byte, 64)
		p := smb2.PacketCodec(pkt)
		p.SetProtocolId()
		p.SetStructureSize()
		p.SetCommand(smb2.SMB2_CREATE)
		p.SetStatus(status)
		p.SetFlags(flags)
		p.SetMessageId(msgID)
		p.SetSessionId(sessionId)
		return pkt
	}

	require := require.New(t)
	const sessionID uint64 = 0xCAFE

	// SMB 3.0.x-style signing-required conn with a CMAC verifier.
	ciph, err := aes.NewCipher(make([]byte, 16))
	require.NoError(err)

	c := &conn{
		outstandingRequests: newOutstandingRequests(),
		requireSigning:      true,
		dialect:             smb2.SMB302,
	}
	s := &session{conn: c, sessionId: sessionID, verifier: cmac.New(ciph)}
	c.session.Store(s)

	t.Run("STATUS_PENDING should skip verification", func(t *testing.T) {
		pkt := makeHdr(uint32(erref.STATUS_PENDING), smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_ASYNC_COMMAND, sessionID, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("regular message, signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, 21)
		pkt.SetSignature(zero[:])
		require.IsType(&InvalidResponseError{}, c.tryVerify(pkt, false))
	})

	t.Run("regular message, unset signed flag, bad signature - should fail", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, smb2.SMB2_CREATE)
		pkt.SetSignature(zero[:])
		err := c.tryVerify(pkt, false)
		require.IsType(&InvalidResponseError{}, err)
		require.ErrorContains(err, "packet failed signature verification")
	})

	t.Run("OPLOCK_BREAK should skip verification", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, 0xFFFFFFFFFFFFFFFF)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("unsigned message, signing not negotiated - succeeds", func(t *testing.T) {
		// we need a connection that doesn't require signing for this subtest
		c := &conn{
			outstandingRequests: newOutstandingRequests(),
			dialect:             smb2.SMB302,
		}
		s := &session{conn: c, sessionId: sessionID}
		c.session.Store(s)

		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, sessionID, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, false))
	})

	t.Run("encrypted message without signature, succeeds", func(t *testing.T) {
		// pass an invalid session id, and use a connection that requires
		// signing to make sure we're getting an early return due to encryption
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR, 0, smb2.SMB2_CREATE)
		require.NoError(c.tryVerify(pkt, true))
	})

	t.Run("signed message succeeds", func(t *testing.T) {
		pkt := makeHdr(0, smb2.SMB2_FLAGS_SERVER_TO_REDIR|smb2.SMB2_FLAGS_SIGNED, sessionID, smb2.SMB2_CREATE)

		// actually sign the packet
		verifier := cmac.New(ciph)
		verifier.Write(pkt)
		pkt.SetSignature(verifier.Sum(nil))

		require.NoError(c.tryVerify(pkt, false))
	})
}

type mockTransport struct {
	writeCalled chan struct{}
	writeBlock  chan struct{}
}

func (m *mockTransport) Write(p []byte) (n int, err error) {
	select {
	case m.writeCalled <- struct{}{}:
	default:
	}
	<-m.writeBlock
	var dummy byte
	for _, b := range p {
		dummy += b
	}
	_ = dummy
	return len(p), nil
}

func (m *mockTransport) ReadSize() (size int, err error) {
	return 0, nil
}

func (m *mockTransport) Read(p []byte) (n int, err error) {
	return 0, nil
}

func (m *mockTransport) Close() error {
	return nil
}

func TestSendWith_ContextCancellationRace(t *testing.T) {
	require := require.New(t)

	writeCalled := make(chan struct{}, 1)
	writeBlock := make(chan struct{})

	tTransport := &mockTransport{
		writeCalled: writeCalled,
		writeBlock:  writeBlock,
	}

	c := &conn{
		t:                   tTransport,
		outstandingRequests: newOutstandingRequests(),
		account:             openAccount(128),
		rdone:               make(chan struct{}, 1),
		wdone:               make(chan struct{}, 1),
		write:               make(chan []byte, 1),
		werr:                make(chan error, 1),
		dialect:             smb2.SMB302,
	}
	go c.runSender()

	ctx, cancel := context.WithCancel(context.Background())

	// Start first sendWith in a separate goroutine.
	var req1 smb2.ReadRequest
	req1.CreditCharge = 1

	sendErrChan := make(chan error, 1)
	go func() {
		_, err := c.send(ctx, &req1)
		sendErrChan <- err
	}()

	// Wait for Write to be called by runSender.
	<-writeCalled

	// Now cancel the context.
	cancel()

	// Immediately start a second sendWith on the same connection.
	// Since sendWith has returned and released c.m, this will try to encode
	// into the same c.encodeBuf.
	// Meanwhile, runSender is still blocked in tTransport.Write (holding a reference
	// to the previous c.encodeBuf content via pkt).
	// This should trigger a data race under -race.
	var req2 smb2.ReadRequest
	req2.CreditCharge = 1

	send2Done := make(chan struct{})
	go func() {
		_, _ = c.send(context.Background(), &req2)
		close(send2Done)
	}()

	// Wait a short time to allow the race to happen under buggy code, then unblock the transport.
	time.Sleep(50 * time.Millisecond)
	close(writeBlock)

	// Wait for sendWith to return.
	err := <-sendErrChan
	if err != nil {
		require.ErrorIs(err, context.Canceled)
	}

	// Clean up.
	<-send2Done
	close(c.wdone)
}

