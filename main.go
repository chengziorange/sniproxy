package main

import (
	"encoding/json"
	"flag"
	"io"
	"io/ioutil"
	"log"
	"net"
	"regexp"
	"sniproxy/internal/sni"
	"strings"
	"sync"
	"time"
)

func main() {
	config, err := initCliParas()
	if err != nil {
		log.Fatal(err)
	}

	for _, rule := range config.Rules {
		rule := rule
		go func() {
			l, err := net.Listen("tcp", rule.ListenAddr)
			if err != nil {
				log.Fatal(err)
			}
			for {
				conn, err := l.Accept()
				if err != nil {
					log.Print(err)
					continue
				}
				go handleConnection(conn, rule.ForwardTargets)
			}
		}()
	}

	select {}
}

type config struct {
	Rules []ruleConfig `json:"rules"`
}

type ruleConfig struct {
	ListenAddr string `json:"listen_addr"`
	// ServerName: ForwardAddress
	ForwardTargets map[string]string `json:"forward_targets"`
}

func initCliParas() (*config, error) {
	configFilePath := flag.String("c", "", "eg. \"config.json\" --- Config file path. Will override other cli params.")
	listenAddr := flag.String("l", ":443", "eg. \"0.0.0.0:443\" --- Listen address and port.")
	forwardTargets := flag.String("f", "", "eg. \"www.baidu.com/112.80.248.75:443,one.one.one.one/[2606:4700:4700::1111]:443\" --- Forward list.")
	flag.Parse()

	var config config

	if *configFilePath == "" {
		ftl := strings.Split(*forwardTargets, ",")
		forwardTargetMap := make(map[string]string)
		for _, v := range ftl {
			pair := strings.Split(v, "/")
			forwardTargetMap[pair[0]] = pair[1]
		}
		// 使用 -l -f 指定配置
		config.Rules = []ruleConfig{{
			ListenAddr:     *listenAddr,
			ForwardTargets: forwardTargetMap,
		}}
	} else {
		jsonBytes, err := ioutil.ReadFile(*configFilePath)
		if err != nil {
			log.Print("Can't read config file!")
			return nil, err
		}
		err = json.Unmarshal(jsonBytes, &config)
		if err != nil {
			log.Print("Can't unmarshal config file!")
			return nil, err
		}
	}

	for _, rule := range config.Rules {
		for serverName, target := range rule.ForwardTargets {
			log.Print("ADD [" + serverName + " -> " + target + "] at [" + rule.ListenAddr + "]")
		}
	}

	return &config, nil
}

func getForwardTarget(serverName string, forwardTargets map[string]string) (target string, allowed bool) {
	if _, ok := forwardTargets[serverName]; ok {
		return forwardTargets[serverName], true
	}
	for keyServerName, valueForwardTarget := range forwardTargets {
		if strings.HasPrefix(keyServerName, "*") {
			keyServerName = ".*(" + strings.ReplaceAll(keyServerName[1:], ".", "\\.") + ")$"
			matched, err := regexp.Match(keyServerName, []byte(serverName))
			if err != nil {
				log.Print("Error when matching sni with allowed sni")
				continue
			}
			if matched {
				return valueForwardTarget, true
			}
		}
	}
	return "", false
}

func handleConnection(clientConn net.Conn, forwardTargets map[string]string) {
	defer func(clientConn net.Conn) {
		if err := clientConn.Close(); err != nil {
			log.Print(err)
		}
	}(clientConn)

	if err := clientConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Print(err)
		return
	}

	clientHello, clientReader, err := sni.PeekClientHello(clientConn)
	if err != nil {
		log.Print(err)
		return
	}

	// 设置为不会超时
	if err := clientConn.SetReadDeadline(time.Time{}); err != nil {
		log.Print(err)
		return
	}

	forwardTarget, ok := getForwardTarget(clientHello.ServerName, forwardTargets)
	if !ok {
		log.Print("Blocking connection to unauthorized backend.")
		log.Print("Source IP: " + clientConn.RemoteAddr().String())
		log.Print("Target SNI: " + clientHello.ServerName)
		return
	}

	backendConn, err := net.DialTimeout("tcp", forwardTarget, 5*time.Second)
	if err != nil {
		log.Print(err)
		return
	}
	defer func(backendConn net.Conn) {
		if err := backendConn.Close(); err != nil {
			log.Print(err)
		}
	}(backendConn)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		if _, err := io.Copy(clientConn, backendConn); err != nil {
			log.Print(err)
		}
		if err := clientConn.(*net.TCPConn).CloseWrite(); err != nil {
			log.Print(err)
		}
		wg.Done()
	}()
	go func() {
		if _, err := io.Copy(backendConn, clientReader); err != nil {
			log.Print(err)
		}
		if err := backendConn.(*net.TCPConn).CloseWrite(); err != nil {
			log.Print(err)
		}
		wg.Done()
	}()

	wg.Wait()
}
