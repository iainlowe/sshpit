package main

import (
	"flag"
	"log"

	"github.com/ilowe/sshpit"
)

var (
	addr   = flag.String("addr", ":22", "address to bind to")
	key    = flag.String("k", "id_rsa", "private server key file")
	logdir = flag.String("logdir", "/var/log/pit", "log dir")
)

func main() {
	flag.Parse()

	log.Printf("v%s starting up...", sshpit.Version)

	sshpit.SetupLogging(*logdir)
	sshpit.NewServer(*addr).Listen()
}
