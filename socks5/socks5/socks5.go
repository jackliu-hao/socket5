package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

var (
	ErrVersionNotSupported       = errors.New("protocol version not supported")
	ErrMethodVersionNotSupported = errors.New("sub-negotiation method version not supported")
	ErrCommandNotSupported       = errors.New("requst command not supported")
	ErrInvalidReservedField      = errors.New("invalid reserved field")
	ErrAddressTypeNotSupported   = errors.New("address type not supported")
)

const (
	SOCKS5Version = 0x05
	ReservedField = 0x00
)

type Server interface {
	Run() error
}

type SOCKS5Server struct {
	IP     string
	Port   int
	Config *Config
}

type Config struct {
	AuthMethod      Method
	PasswordChecker func(username, password string) bool
}

func initConfig(config *Config) error {
	if config.AuthMethod == MethodPassword && config.PasswordChecker == nil {
		return ErrPasswordCheckerNotSet
	}
	return nil
}

func (s *SOCKS5Server) Run() error {
	// Initialize server configuration
	if err := initConfig(s.Config); err != nil {
		return err
	}

	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	//开启监听，等待连接
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	fmt.Println(s.Port," 端口开启成功，等待连接....")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("connection failure from %s: %s", conn.RemoteAddr(), err)
			continue
		}

		go func() {
			defer conn.Close()
			err := handleConnection(conn, s.Config)
			if err != nil {
				log.Printf("handle connection failure from %s: %s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn, config *Config) error {
	// 协商过程
	if err := auth(conn, config); err != nil {
		return err
	}

	// 请求过程
	targetConn, err := request(conn)
	if err != nil {
		return err
	}
	if targetConn != nil {
		return forward(conn, targetConn)
	}
	return errors.New("和目标服务连接失败")
	// 转发过程
}

//conn 是客户端和我建立的连接
//targetConn 是我和目标建立的连接
func forward(conn io.ReadWriter, targetConn io.ReadWriteCloser) error {
	defer targetConn.Close()
	remoteConn := conn.(net.Conn)
	target := targetConn.(net.Conn)
	fmt.Println( remoteConn.RemoteAddr() ," ===>  localhost  <====",target.RemoteAddr())

	go io.Copy(targetConn, conn)
	_, err := io.Copy(conn, targetConn)
	return err
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	//接收请求阶段 客户端发送过来的数据
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}

	// Check if the command is supported
	if message.Cmd != CmdConnect {
		return nil, WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
	}
	// Check if the address type is supported
	if message.AddrType == TypeIPv6 {
		return nil, WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
	}

	// 请求访问目标TCP服务
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, WriteRequestFailureMessage(conn, ReplyConnectionRefused)
	}

	// Send success reply
	addrValue := targetConn.LocalAddr() //本地的 IP:PORT
	addr := addrValue.(*net.TCPAddr) //断言
	return targetConn, WriteRequestSuccessMessage(conn, addr.IP, uint16(addr.Port))
}

func auth(conn io.ReadWriter, config *Config) error {
	// Read client auth message
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}

	// Check if the auth method is supported
	var acceptable bool
	for _, method := range clientMessage.Methods {
		if method == config.AuthMethod {
			acceptable = true
		}
	}
	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method not supported")
	}
	//服务端向客户端发送数据
	if err := NewServerAuthMessage(conn, config.AuthMethod); err != nil {
		return err
	}

	//如果是密码认证
	if config.AuthMethod == MethodPassword {
		cpm, err := NewClientPasswordMessage(conn)
		if err != nil {
			return err
		}

		if !config.PasswordChecker(cpm.Username, cpm.Password) {
			WriteServerPasswordMessage(conn, PasswordAuthFailure)
			return ErrPasswordAuthFailure
		}

		//认证成功
		if err := WriteServerPasswordMessage(conn, PasswordAuthSuccess); err != nil {
			return err
		}
	}

	return nil
}