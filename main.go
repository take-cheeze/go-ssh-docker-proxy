package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os/user"
	"path/filepath"

	"golang.org/x/crypto/ssh"
	"github.com/fsouza/go-dockerclient"
)

var (
	dockerClient *docker.Client
)

func main() {
	user, err := user.Current()
	if err != nil {
		log.Fatal("Failed gatting user information: ", err)
	}
	home := user.HomeDir

	authorizedKeysMap := map[string]bool{}

	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		// Remove to disable public key auth.
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile(filepath.Join(home, ".ssh", "id_rsa"))
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	dockerClient, err = docker.NewClientFromEnv()
	if err != nil {
		log.Fatal("failed starting docker client: ", err)
	}

	log.Print("Started server:")
	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}

		go func() {
			err = runServer(nConn, config)
			if err != nil {
				log.Print("failed runServer: ", err)
			}
		}()
	}
}

func runServer(nConn net.Conn, config *ssh.ServerConfig) error {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return err
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return err
		}

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell", "pty-req":
					req.Reply(true, nil)
				default:
					log.Print(req.Type, " payload: ", string(req.Payload))
				}
			}
		}(requests)

		log.Print("Starting to run on docker container: ", conn.User())

		exec, err := dockerClient.CreateExec(docker.CreateExecOptions{
			AttachStdin: true,
			AttachStdout: true,
			AttachStderr: true,
			Tty: true,
			Cmd: []string{"/bin/bash"},
			Container: conn.User(),
		})
		if err != nil {
			return err
		}

		err = dockerClient.StartExec(exec.ID, docker.StartExecOptions {
			InputStream: channel,
			OutputStream: channel,
			ErrorStream: channel.Stderr(),
			Tty: true,
			// Detach: true,
			RawTerminal: true,
		})
		if err != nil {
			return err
		}

	}
	log.Print("End to run on docker container: ", conn.User())

	return nil
}
