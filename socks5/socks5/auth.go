package socks5

import (
	"errors"
	"io"
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

type ClientPasswordMessage struct {
	Username string
	Password string
}

type Method = byte

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

const (
	PasswordMethodVersion = 0x01
	PasswordAuthSuccess   = 0x00
	PasswordAuthFailure   = 0x01
)

var (
	ErrPasswordCheckerNotSet = errors.New("error password checker not set")
	ErrPasswordAuthFailure   = errors.New("error authenticating username/password")
)

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	// Read version, nMethods
	buf := make([]byte, 2)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	// Validate version
	if buf[0] != SOCKS5Version {
		return nil, ErrVersionNotSupported
	}

	// Read methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}

	return &ClientAuthMessage{
		Version:  SOCKS5Version,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}
//服务端向客户端发送数据
func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5Version, method}
	_, err := conn.Write(buf)
	return err
}

//密码认证 , 读取客户端发送过来的用户名和密码
func NewClientPasswordMessage(conn io.Reader) (*ClientPasswordMessage, error) {
	// Read version and username length
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	version, usernameLen := buf[0], buf[1]
	if version != PasswordMethodVersion {
		return nil, ErrMethodVersionNotSupported
	}

	// Read username, password length
	buf = make([]byte, usernameLen+1)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	username, passwordLen := string(buf[:len(buf)-1]), buf[len(buf)-1]

	// Read password
	if len(buf) < int(passwordLen) {
		buf = make([]byte, passwordLen)
	}
	if _, err := io.ReadFull(conn, buf[:passwordLen]); err != nil {
		return nil, err
	}

	return &ClientPasswordMessage{
		Username: username,
		Password: string(buf[:passwordLen]),
	}, nil
}

func WriteServerPasswordMessage(conn io.Writer, status byte) error {
	_, err := conn.Write([]byte{PasswordMethodVersion, status})
	return err
}