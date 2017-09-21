// Copyright © 2017 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// decodeCmd represents the decode command
var decodeCmd = &cobra.Command{
	Use:   "decode",
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: decodeMain,
}

var (
	fFilePath string
)

func init() {
	RootCmd.AddCommand(decodeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// decodeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	flags := decodeCmd.Flags()
	flags.StringVarP(&fFilePath, "file", "f", "shadowsock.json", "File to save json")

}

func decodeMain(cmd *cobra.Command, args []string) {
	f, _ := os.Create(fFilePath)
	defer f.Close()
	for _, uri := range args {
		var data []byte
		// var server string
		if strings.HasPrefix(uri, "ss://") {
			ss := serverFromSS(uri)
			data, _ = json.MarshalIndent(ss, "", "    ")
			// server = ss.Server
		} else if strings.HasPrefix(uri, "ssr://") {
			ssr := serverFromSSR(uri)
			data, _ = json.MarshalIndent(ssr, "", "    ")
			// server = ssr.Server
		}
		fmt.Printf(string(data))
		f.Write(data)
	}
}

type SSServer struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
	Password   string `json:"password"`
	Method     string `json:"method"`

	LocalAddr string `json:"local_address"` // "127.0.0.1"
	LocalPort int    `json:"local_port"`    // 1080
	FastOpen  bool   `json:"fast_open"`     // false
	Workers   int    `json:"workers"`       // 1
	Timeout   int    `json:"timeout"`       // 120
}

type SSRServer struct {
	SSServer

	ServerIpv6    string `json:"server_ipv6,omitempty"`   // "::"
	Proto         string `json:"protocol"`                // "auth_aes128_md5"
	ProtoParam    string `json:"protocolparam,omitempty"` // "" 每个端口的最大连接数
	Obfs          string `json:"obfs"`                    // "tls1.2_ticket_auth_compatible"
	ObfsParam     string `json:"obfsparam,omitempty"`     // ""
	Redirect      string `json:"redirect,omitempty"`      // ""
	DnsIpv6       bool   `json:"dns_ipv6,omitempty"`      // false 是否优先使用ipv6地址
	UdpOverTcp    bool   `json:"udp_over_tcp,omitempty"`  // false
	ServerUdpPort int    `json:"server_udp_port,omitempty"`
	UdpTimeout    int    `json:"udp_timeout,omitempty"`
	Group         string `json:"group,omitempty"`

	speed_limit_per_con  int // 0
	speed_limit_per_user int // 0
	remarks              string
}

func serverFromSS(uri string) *SSServer {
	uriPat := `^ss://([A-Za-z0-9+-/=_]+)(#(.+))?`
	uriReg := regexp.MustCompile(uriPat)
	detailPat := `^(?P<method>.+):(?P<password>.*)@(?P<hostname>.+?):(?P<port>\d+?)$`
	detailReg := regexp.MustCompile(detailPat)

	match := uriReg.FindStringSubmatch(uri)
	decodeBytes, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		fmt.Println(err)
	}
	match = detailReg.FindStringSubmatch(string(decodeBytes))
	port, _ := strconv.Atoi(match[4])

	return &SSServer{
		Method:     match[1],
		Password:   match[2],
		Server:     match[3],
		ServerPort: port,
		LocalAddr:  "127.0.0.1",
		LocalPort:  1080,
		Timeout:    120,
		FastOpen:   false,
		Workers:    4,
	}
}

// ssr://host:port:protocol:method:obfs:base64pass/?obfsparam=urlbase64&remarks=urlbase64&group=urlbase64&udpport=0&uot=1
func serverFromSSR(uri string) *SSRServer {
	uriPat := `^ssr://([A-Za-z0-9_-]+)`
	uriReg := regexp.MustCompile(uriPat)
	match := uriReg.FindStringSubmatch(uri)

	data, err := base64.StdEncoding.DecodeString(match[1])
	if err != nil {
		fmt.Println(err)
	}

	parts := bytes.Split(data, []byte("/?"))
	detail := bytes.Split(parts[0], []byte(":"))
	password, _ := base64.StdEncoding.DecodeString(string(detail[5]))
	server_port, _ := strconv.Atoi(string(detail[1]))

	ss := SSServer{
		Server:     string(detail[0]),
		ServerPort: server_port,
		Method:     string(detail[3]),
		Password:   string(password),
		LocalAddr:  "127.0.0.1",
		LocalPort:  1080,
		Timeout:    120,
		FastOpen:   false,
		Workers:    4,
	}

	protocol := "origin"
	if len(detail[2]) > 0 {
		protocol = strings.Replace(string(detail[2]), "_compatible", "", -1)
	}
	obfs := "plain"
	if len(detail[4]) > 0 {
		obfs = strings.Replace(string(detail[4]), "_compatible", "", -1)
	}
	ssr := &SSRServer{
		SSServer: ss,
		Proto:    protocol,
		Obfs:     obfs,
		Group:    "",
	}
	params := bytes.Split(parts[1], []byte("$"))
	for _, param := range params {
		pairs := bytes.Split(param, []byte{'='})
		key := string(pairs[0])
		value, _ := base64.URLEncoding.DecodeString(string(pairs[1]))
		val := string(value)
		switch key {
		case "obfsparam":
			ssr.ObfsParam = val
		case "remarks":
			ssr.remarks = val
		case "group":
			ssr.Group = val
		case "udpport":
			ssr.ServerUdpPort, _ = strconv.Atoi(val)
		case "uot":
			ssr.UdpOverTcp = val != "0"
		default:
			fmt.Println("unknown key-value[%s:%s]", key, val)
		}
	}

	return ssr
}
