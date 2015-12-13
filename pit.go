// A small SSH daemon providing bash sessions
//
// Server:
// cd my/new/dir/
// #generate server keypair
// ssh-keygen -t rsa
// go get -v .
// go run sshd.go
//
// Client:
// ssh foo@localhost -p 2200 #pass=bar

package sshpit

import (
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/kr/pty"
	"golang.org/x/crypto/ssh"
)

const Version string = "NONINJECTED"

var logdir string

func init() {
	rand.Seed(time.Now().Unix())

}

func SetupLogging(dir string) {
	logdir = dir
	if _, err := os.Stat(logdir); err != nil {
		os.MkdirAll(logdir, 0777)
	}

	path := filepath.Join(logdir, "access.log")
	f, err := os.Open(path)
	if err != nil {
		f, err = os.Create(path)
		if err != nil {
			log.Fatalln("couldn't setup logging!", err)
		}
	}

	log.SetOutput(io.MultiWriter(f, os.Stderr))
	log.Println("logging to", logdir)
}

func getConfig() *ssh.ServerConfig {
	config := &ssh.ServerConfig{
		//Define a function to run when a client attempts a password login
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			log.Printf(`{"user": "%s", "pass": "%s"}`, c.User(), string(pass))
			return nil, nil
		},
		// NoClientAuth: true,
	}

	// You can generate a keypair with 'ssh-keygen -t rsa'
	key, _ := rsa.GenerateKey(cryptorand.Reader, 2048)
	privateBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key),
		},
	)

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key")
	}

	config.AddHostKey(private)
	return config
}

// In the latest version of crypto/ssh (after Go 1.3), the SSH server type has been removed
// in favour of an SSH connection type. A ssh.ServerConn is created by passing an existing
// net.Conn and a ssh.ServerConfig to ssh.NewServerConn, in effect, upgrading the net.Conn
// into an ssh.ServerConn
type Server struct {
	listener net.Listener
	config   *ssh.ServerConfig
}

func NewServer(addr string) (s *Server) {
	var (
		err error
	)

	s = &Server{}

	if s.listener, err = net.Listen("tcp", addr); err != nil {
		log.Printf("server: error listening on %s (%s)\n", addr, err)
	}

	s.config = getConfig()

	log.Print("server: listening on ", s.listener.Addr().String())

	return
}

func (s *Server) Listen() {
	for {
		var (
			se  *Session
			err error
		)

		se = NewSession()

		if se.conn, err = s.listener.Accept(); err != nil {
			log.Printf("Failed to accept incoming connection (%s)", err)
			continue
		}

		// Before use, a handshake must be performed on the incoming net.Conn.
		if se.srvconn, se.newchans, se.reqs, err = ssh.NewServerConn(se.conn, s.config); err != nil {
			log.Printf("Failed to handshake (%s)", err)
			continue
		}

		// Discard all global out-of-band Requests
		go ssh.DiscardRequests(se.reqs)

		se.logf("new SSH connection from %s (%s)", se.srvconn.RemoteAddr(), se.srvconn.ClientVersion())

		// Accept all channels
		go se.handleChannels()
	}
}

func (s *Session) handleChannels() {
	// Service the incoming Channel channel in go routine
	for newChannel := range s.newchans {
		go s.handleChannel(newChannel)
	}
}

type Session struct {
	conn     net.Conn
	srvconn  *ssh.ServerConn
	newchans <-chan ssh.NewChannel
	reqs     <-chan *ssh.Request
	id       string
}

func NewSession() *Session {
	s := &Session{}

	s.id = fmt.Sprintf("%x", time.Now().Unix())

	return s
}
func (s *Session) logln(a ...interface{})          { log.Println(append([]interface{}{s.id + ":"}, a...)...) }
func (s *Session) logf(m string, a ...interface{}) { log.Printf(s.id+": "+m, a...) }

func (s *Session) handleChannel(newChannel ssh.NewChannel) {
	// Since we're handling a shell, we expect a
	// channel type of "session". The also describes
	// "x11", "direct-tcpip" and "forwarded-tcpip"
	// channel types.
	if t := newChannel.ChannelType(); t != "session" {
		newChannel.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %s", t))
		return
	}

	// At this point, we have the opportunity to reject the client's
	// request for another logical connection
	connection, requests, err := newChannel.Accept()
	if err != nil {
		s.logf("Could not accept channel (%s)", err)
		return
	}

	// Sessions have out-of-band requests such as "shell", "pty-req" and "env"
	go func() {

		// Fire up bash for this session
		bash := exec.Command("/usr/bin/docker", "run", "-ti", "--net=none", "ilowe/pit")
		fname := s.id + ".log"
		f, _ := os.Create(filepath.Join(logdir, fname))
		f.WriteString("####################################################################################\n## Source Address: " + s.srvconn.RemoteAddr().String() + "\n## Timestamp: " + time.Now().String() + "\n####################################################################################\n")

		// Prepare teardown function
		close := func() {
			connection.Close()
			f.Close()
			_, err := bash.Process.Wait()
			if err != nil {
				s.logf("failed to exit bash (%s)", err)
			}
			s.logf("session closed")
		}

		// Allocate a terminal for this channel
		// log.Print("Creating pty...")
		bashf, err := pty.Start(bash)
		if err != nil {
			s.logf("could not start pty (%s)", err)
			close()
			return
		}

		for req := range requests {
			switch req.Type {
			case "exec":
				cmdstr := strings.TrimSpace(string(req.Payload[3:]))
				s.logf("EXEC: %s", cmdstr)
				bash := exec.Command("/usr/bin/docker", "run", "-ti", "--net=none", "ilowe/pit", "/bin/sh")
				bash.Args = append(bash.Args, strings.Split(cmdstr, " ")...)
				bash.Stdout = connection
				bash.Stderr = connection
				bash.Run()
				req.Reply(false, nil)
				close()
				return
			case "shell":
				s.logln("shell req")

				//pipf10e session to bash and visa-versa
				var once sync.Once
				go func() {
					mw := io.MultiWriter(connection, f)

					io.Copy(mw, bashf)
					once.Do(close)
				}()
				go func() {
					io.Copy(bashf, connection)
					once.Do(close)
				}()
			case "pty-req":
				s.logln("pty-req")
				termLen := req.Payload[3]
				w, h := parseDims(req.Payload[termLen+4:])
				SetWinsize(bashf.Fd(), w, h)
				// Responding true (OK) here will let the client
				// know we have a pty ready for input
				req.Reply(true, nil)
			case "window-change":
				s.logln("window-change")
				w, h := parseDims(req.Payload)
				SetWinsize(bashf.Fd(), w, h)
				req.Reply(true, nil)
			}
		}
	}()
}

// =======================

// parseDims extracts terminal dimensions (width x height) from the provided buffer.
func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// ======================

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}

// Borrowed from https://github.com/creack/termios/blob/master/win/win.go
