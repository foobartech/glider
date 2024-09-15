// Copyright 2022 hev, r@hev.cc
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

package ip4p

import (
	"net"
	"strconv"

	"github.com/nadoo/glider/pkg/log"
)

func parseIp4p(hostname string) string {
	ips, err := net.LookupIP(hostname)
	if err != nil {
		log.F("[ip4p] LookupIP err: %v", err)
	} else {
		for _, ip := range ips {
			if len(ip) == 16 {
				if ip[0] == 0x20 && ip[1] == 0x01 &&
					ip[2] == 0x00 && ip[3] == 0x00 {
					hostname = net.IPv4(ip[12], ip[13], ip[14], ip[15]).String() + ":" + strconv.Itoa(int(ip[10])<<8|int(ip[11]))
					log.F("[ip4p] parse ip4p result: %v", hostname)
					break
				}
			}
		}
	}
	return hostname
}

func parseTxt(hostname string) string {
	txts, err := net.LookupTXT(hostname)
	if err != nil {
		log.F("[ip4p] LookupTXT err: %v", err)
	} else {
		for _, txt := range txts {
			_, _, err := net.SplitHostPort(txt)
			if err == nil {
				hostname = txt
				log.F("[ip4p] LookupTXT result: %v", hostname)
			}
		}
	}
	return hostname
}

func LookupIP4P(addr string) string {
	hostname, port, err := net.SplitHostPort(addr)
	if err != nil {
		log.F("[ip4p] SplitHostPort err: %v", err)
		return addr
	}
	// addr 可能为 :443 只有端口，字符串必须用双引号
	if hostname == "" {
		// log.F("[ip4p] Empty hostname")
		return addr
	}
	// log.F("hostname %v", hostname)
	ip := net.ParseIP(hostname)
	if ip != nil {
		// log.F("[ip4p] hostname is ip: %v", ip)
		return addr
	}
	targetAddr := ""
	if port == "1" {
		targetAddr = parseIp4p(hostname)
	} else if port == "2" {
		targetAddr = parseTxt(hostname)
	} else if port == "0" {
		targetAddr = parseIp4p(hostname)
		if targetAddr == hostname {
			targetAddr = parseTxt(hostname)
		}
	}
	if targetAddr != hostname {
		addr = targetAddr
	}
	return addr
}
