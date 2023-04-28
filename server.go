package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"

	quic "github.com/quic-go/quic-go"
	cli "github.com/urfave/cli/v2"
	"golang.org/x/net/context"
)

func server(c *cli.Context) error {
	// generate TLS certificate
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return err
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quicssh"},
	}

	// configure listener
	listener, err := quic.ListenAddr(c.String("bind"), config, nil)
	if err != nil {
		return err
	}
	defer listener.Close()
	destination := strings.Split(c.String("destination"), ":")
	port := 22
	if len(destination) == 2 {
		port, err = strconv.Atoi(destination[1])
		if err != nil {
			log.Printf("port parsing error: %v", err)
			return err
		}
	}
	log.Printf("Listening at %q and forwarding it to \"%s:%d\"...", c.String("bind"), destination[0], port)
	destAddr := net.TCPAddr{IP: net.ParseIP(destination[0]), Port: port}
	ctx := context.Background()
	for {
		log.Printf("Accepting connection...")
		connection, err := listener.Accept(ctx)
		if err != nil {
			log.Printf("listener error: %v", err)
			continue
		}

		go serverSessionHandler(ctx, connection, destAddr)
	}
	return nil
}

func serverSessionHandler(ctx context.Context, connection quic.Connection, destAddr net.TCPAddr) {
	log.Printf("hanling connection...")
	defer connection.CloseWithError(0, "close")
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			log.Printf("connection error: %v", err)
			break
		}
		go serverStreamHandler(ctx, stream, destAddr)
	}
}

func serverStreamHandler(ctx context.Context, conn io.ReadWriteCloser, destAddr net.TCPAddr) {
	log.Printf("handling stream...")
	defer conn.Close()

	rConn, err := net.DialTCP("tcp", nil, &destAddr)
	if err != nil {
		log.Printf("dial error: %v", err)
		return
	}
	defer rConn.Close()

	ctx, cancel := context.WithCancel(ctx)

	var wg sync.WaitGroup
	wg.Add(2)
	c1 := readAndWrite(ctx, conn, rConn, &wg)
	c2 := readAndWrite(ctx, rConn, conn, &wg)
	select {
	case err = <-c1:
		if err != nil {
			log.Printf("readAndWrite error on c1: %v", err)
			return
		}
	case err = <-c2:
		if err != nil {
			log.Printf("readAndWrite error on c2: %v", err)
			return
		}
	}
	cancel()
	wg.Wait()
	log.Printf("Piping finished")
}

func netCopy(input io.Reader, output io.Writer) (err error) {
	buf := make([]byte, 8192)
	for {
		count, err := input.Read(buf)
		if err != nil {
			if err == io.EOF && count > 0 {
				output.Write(buf[:count])
			}
			break
		}
		if count > 0 {
			log.Println(buf, count)
			output.Write(buf[:count])
		}
	}
	return
}
