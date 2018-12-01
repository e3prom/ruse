// Ruse, a multi-platform HTTP(S) redirector
// Copyright 2018 The Ruse AUTHORS. All rights reserved.
//
// Use of this source code is governed by a GPLv3 license that can be found in
// the LICENSE file.
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Global program constants.
const (
	CONFIG_FILE = "/etc/ruse.conf"
)

// Global program variables.
var configFile = CONFIG_FILE
var proto = make(map[string]struct{})

// Configuration File Structure.
type Config struct {
	// Hostname to bind the HTTP listener on.
	Hostname string
	// Local HTTP port to listen to.
	Port int
	// Local HTTPS (SSL/TLS) port to listen to.
	TLSPort int
	// Enabled protocols
	// plain == plain-text HTTP
	// ssl == SSL/TLS HTTPS
	Protocols []string
	// TLS server key
	TLSKey string
	// TLS server certificate chain
	TLSCert string
	// Root path to serve content from.
	Root string
	// Directory Index file.
	Index string
	// Verbose flag:
	// 0 == turn off verbosity.
	// 1 == low verbose level.
	// 2 == medium verbose level.
	// 3 == high verbose level.
	Verbose int
	// Logging File.
	LogFile string
	// Proxy settings.
	Proxy []Proxy
}

// Proxy struct definition
type Proxy struct {
	Type   string
	Match  Match
	Target string
}

// Match struct definition
type Match struct {
	UserAgent []string
	Network   []string
}

// init function for the flag package.
func init() {
	flag.StringVar(&configFile, "c", CONFIG_FILE, "configuration file")
}

// main function which essentially get the Config struct pointer back from
// 'initAndParseConfig()', prints informational messages to the user's terminal
// when verbosity is enabled, and starts the the built-in HTTP and/or HTTPS
// server(s). The HTTP server is conditionally started in a seperate go
// routine, so it doesn't not block the start of the TLS server.
func main() {
	// parse command-line parameters
	flag.Parse()

	// parse configuration file
	var config *Config = initAndParseConfig(configFile)
	http.HandleFunc("/", getContentWithConfig(config))

	// trigger file logging
	if config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatal("error opening log file: %s", err)
		}
		defer f.Close()

		log.SetOutput(f)
		log.Println("file logging started")
	}

	// check if plain-text HTTP is enabled.
	if _, present := proto["plain"]; present {
		hostPort := []string{} // GPWHYL: build a slice of strings
		hostPort = append(hostPort, config.Hostname)
		hostPort = append(hostPort, ":")
		hostPort = append(hostPort, strconv.Itoa(config.Port))
		if config.Verbose > 0 {
			fmt.Printf("Starting HTTP Server on %s:%d\n", config.Hostname,
				config.Port)
		}
		// if TLS is also enabled, starts a new go routine.
		if _, present := proto["tls"]; present {
			go func() {
				log.Fatal(http.ListenAndServe(strings.Join(hostPort, ""), nil))
			}()
		} else {
			log.Fatal(http.ListenAndServe(strings.Join(hostPort, ""), nil))
		}
	}

	// if TLS is enabled, uses http.ListenAndServeTLS().
	if _, present := proto["tls"]; present {
		hostTLSPort := []string{}
		hostTLSPort = append(hostTLSPort, config.Hostname)
		hostTLSPort = append(hostTLSPort, ":")
		hostTLSPort = append(hostTLSPort, strconv.Itoa(config.TLSPort))
		if config.Verbose > 0 {
			fmt.Printf("Starting HTTPS Server on %s:%d\n", config.Hostname,
				config.TLSPort)
		}
		log.Fatal(http.ListenAndServeTLS(strings.Join(hostTLSPort, ""),
			config.TLSCert, config.TLSKey, nil))
	}
}

// checkToProxy simply checks if the incoming request's user-agent matches any
// of the configured proxy matching criterias. If it does, it returns true.
func checkToProxy(w http.ResponseWriter, r *http.Request, config *Config) bool {
	// declare and initialize isMatchedNetwork and isMatchUserAgent to false.
	var isMatchedNetwork bool = false
	var isMatchedUserAgent bool = false

	// set clientAddr to the request's client address.
	clientAddr := strings.Split(r.RemoteAddr, ":")

	// For every Proxy definition:
	for _, c := range config.Proxy {
		// for every CIDR networks specified as matching criteria, call
		// isAddrInNetwork() with the client IP address. If it returns True
		// then set the 'isMatchedNetwork' to True as well.
		for _, n := range c.Match.Network {
			// if it starts with an exclamation mark character.
			if n[0] == 0x21 {
				if isAddrInNetwork(clientAddr[0], n[1:]) {
					isMatchedNetwork = false
					break // do not eval further.
				}
			} else {
				if isAddrInNetwork(clientAddr[0], n) {
					isMatchedNetwork = true
				}
			}
		}
		// for every User-Agent specified as matching criteria, check if the
		// request's User-Agent header field matches. If it does, set
		// isMatchedUseragent to True.
		for _, ua := range c.Match.UserAgent {
			if r.UserAgent() == ua {
				isMatchedUserAgent = true
			}
		}

		// if both matching criteria are True, then perform proxying.
		if isMatchedUserAgent && isMatchedNetwork {
			performProxying(w, r, c.Target)
			return true
		}
	}
	// if no Proxy definition matched, return False.
	return false
}

// isAddrInNetwork takes a client address and a CIDR network as arguments,
// parses and converts them in their appropriate types. The function will
// returns True if the passed network is "" (empty) OR the boolean result of
// the call to the 'Contains' methods. The latter returns True is the IP is
// inside the CIDR network, or False otherwise.
func isAddrInNetwork(cAddr string, cNet string) bool {
	if cNet != "" {
		_, n, err := net.ParseCIDR(cNet)
		if err != nil {
			log.Printf("error while parsing CIDR network %s.", cNet)
			return false
		}
		ip := net.ParseIP(cAddr)
		return n.Contains(ip)
	} else {
		return true
	}
}

// getContentWithConfig wrapper function used to get pointer to the
// configuration's structure. It wraps the HTTP handler function which serves
// files recursively from the web root directory and the request's URL path as
// retured by the sanitizePath() function.
func getContentWithConfig(config *Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		processPath := func(p string) string {
			// regexp for directories in the path string 'p'.
			r := regexp.MustCompile(".*/$")
			if r.MatchString(p) {
				// serve index file instead of the default directory listing.
				p = p + config.Index
			}
			return path.Clean(p)
		}
		// call checkToProxy() to determine if the requests need to be proxied.
		// if not serve files and call processPath to sanitize the url path.
		if !checkToProxy(w, r, config) {
			// print client requests to log
			if config.Verbose > 1 {
				log.Printf(": %s - \"%s %s %s\" - \"%s\"\n", r.RemoteAddr,
					r.Method, r.URL, r.Proto, r.UserAgent())
			}
			http.ServeFile(w, r, filepath.Join(config.Root,
				processPath(r.URL.Path)))
		}
	}
}

// performProxying function parses the given target 't' into an URL structure.
// it then create a reverse proxy HTTP handler using the net/http/httputil
// package's NewSingleHostReverseProxy() function. The Request structure
// headers are updated to match the target to proxy traffic to. The ServeHTTP()
// function creates the handler to handle the reverse proxy operation
// (non-blocking) using go routines.
func performProxying(w http.ResponseWriter, r *http.Request, t string) {
	url, _ := url.Parse(t)
	proxy := httputil.NewSingleHostReverseProxy(url)

	r.URL.Host = url.Host
	r.URL.Scheme = url.Scheme
	r.Host = url.Host
	r.Header.Set("X-Forwarded-Host", r.Header.Get("Host"))

	// create new Transport
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
	}

	proxy.ServeHTTP(w, r)
}

// initAndParseConfig function dedicated to the declaration and initialization
// of the Config structure and the parsing of the JSON formatted configuration
// file. Upon successful parsing of the config file, it returns a pointer to
// the Config structure.
func initAndParseConfig(cf string) *Config {
	config := Config{}

	// Set default values for the important members of the Config structure.
	config.Hostname = "localhost"
	config.Port = 8000
	config.TLSPort = 443
	config.TLSKey = "server.key"
	config.TLSCert = "server.crt"
	config.Protocols = []string{"plain"}
	config.Root = "/var/www"
	config.LogFile = ""

	f, err := os.Open(cf)
	if err != nil {
		fmt.Printf("error cannot open configuration file: %s\n", configFile)
		os.Exit(1)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	err = dec.Decode(&config)
	if err != nil {
		fmt.Printf("error while reading configuration file: %v\n", err)
		os.Exit(1)
	}

	// create the protocols map using the global-scope 'proto' map.
	proto = make(map[string]struct{}, len(config.Protocols))
	for _, s := range config.Protocols {
		proto[s] = struct{}{}
	}

	return &config
}
