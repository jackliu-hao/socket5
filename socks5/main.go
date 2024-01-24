package main

import (
	"flag"
	socks5 "hao.com/mySocks5"
	"log"
)


func main() {

	// 定义命令行参数
	var port int

	flag.IntVar(&port, "p", 1080, "开启的端口号")

	// 解析命令行参数
	flag.Parse()

	users := map[string]string{
		"admin":    "123456",
		"zhangsan": "1234",
		"lisi":     "abde",
	}

	server := socks5.SOCKS5Server{
		IP:   "localhost",
		Port: port,
		Config: &socks5.Config{
			AuthMethod: socks5.MethodNoAuth,
			PasswordChecker: func(username, password string) bool {
				wantPassword, ok := users[username]
				if !ok {
					return false
				}
				return wantPassword == password
			},
		},
	}

	err := server.Run()
	if err != nil {
		log.Fatal(err)
	}
}