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
	"os/signal"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Global program constants.
const (
	CONFIG_FILE = "/etc/ruse.conf"
	INDEX_FILE  = "index.htm"
)

// Global program variables.
var (
	configFile = CONFIG_FILE
	indexFile  = INDEX_FILE
	proto      = make(map[string]struct{})
)

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
	UserAgent    []string
	Network      []string
	_userAgent   []string
	_reUserAgent []*regexp.Regexp
}

// init function for the flag package.
func init() {
	flag.StringVar(&configFile, "c", CONFIG_FILE, "path to ruse configuration file")
	flag.StringVar(&indexFile, "i", INDEX_FILE, "filename of directory index")
}

// SIGHUP handler function.
// This function create and setup the channel for the Unix signal notifications
// and returns the signal channel to the caller.
func handleSIGHUP() chan os.Signal {
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGHUP)

	return sc
}

// main function which essentially get the Config struct pointer back from
// 'initAndParseConfig()', prints informational messages to the user's terminal
// when verbosity is enabled, and starts the the built-in HTTP and/or HTTPS
// server(s). The HTTP server is conditionally started in a seperate go
// routine, so it doesn't not block the start of the TLS server.
func main() {
	// parse command-line parameters.
	flag.Parse()

	// Uses flag.Visit to visit flags, calling the passed function for each.
	// The latter will sets the *actual* flags inside the 'flagset' map.
	flagset := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { flagset[f.Name] = true })

	// declare and initialize configuration structure.
	config := Config{}

	// create a goroutine to handle Unix signals. it will block until a signal
	// is received through the channel setup by the handleSIGHUP() function.
	// When a signal is received, 's' gets the signal name and we respectively
	// init and parse again the configuration structure and file.
	go func() {
		for {
			s := <-handleSIGHUP()
			log.Printf("signal: got %s signal, reloading configuration file...", s)
			initAndParseConfig(configFile, &config)
		}
	}()

	// parse configuration file.
	initAndParseConfig(configFile, &config)

	// check if the 'indexFile' command-line flag is set.
	// if set, it will overwrite the config's Index string, as it takes
	// precedence over the configuration and their default values.
	if flagset["i"] {
		config.Index = indexFile
		if config.Verbose > 1 {
			log.Printf("warning: Directory Index is set to %v\n", config.Index)
		}
	}

	// compile hard-coded directory regexp once.
	reDir := regexp.MustCompile(".*/$")

	// register call back function for handling HTTP traffic.
	http.HandleFunc("/", getContentWithConfig(&config, reDir))

	// trigger file logging.
	if config.LogFile != "" {
		f, err := os.OpenFile(config.LogFile,
			os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			log.Fatalf("error opening log file: %s", err)
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
	for _, p := range config.Proxy {
		// for every CIDR networks specified as matching criteria, call
		// isAddrInNetwork() with the client IP address. If it returns True
		// then set the 'isMatchedNetwork' to True as well.
		for _, n := range p.Match.Network {
			// if it starts with an exclamation mark character.
			// bug fix: to avoid triggering index out-of-range errors, first
			// ensure the referenced array has at least one element.
			if (len(n) > 0) && (n[0] == 0x21) {
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
		for _, ua := range p.Match._userAgent {
			if r.UserAgent() == ua {
				isMatchedUserAgent = true
			}
		}

		// for every pre-compiled UA's regexp, perform matching.
		for _, re := range p.Match._reUserAgent {
			if re.MatchString(r.UserAgent()) {
				isMatchedUserAgent = true
			}
		}

		// finally, if both matching criteria are True, then perform proxying.
		if isMatchedUserAgent && isMatchedNetwork {
			performProxying(w, r, p.Target)
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
func getContentWithConfig(config *Config, re *regexp.Regexp) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		processPath := func(p string) string {
			// regexp for directories in the path string 'p'.
			if re.MatchString(p) {
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
				log.Printf("static: %s - \"%s %s %s\" - \"%s\"\n", r.RemoteAddr,
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
// file.
func initAndParseConfig(cf string, config *Config) {
	// Set default values for the mandatory members of the Config structure.
	config.Hostname = "localhost"
	config.Port = 8000
	config.TLSPort = 443
	config.TLSKey = "server.key"
	config.TLSCert = "server.crt"
	config.Protocols = []string{"plain"}
	config.Root = "/var/www"
	config.Index = ""
	config.LogFile = ""

	f, err := os.Open(cf)
	if err != nil {
		fmt.Printf("error cannot open configuration file: %s\n", configFile)
		os.Exit(1)
	}
	defer f.Close()

	dec := json.NewDecoder(f)

	// decode the configuration file and fill the passed-by-reference
	// structure.
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

	// if regular expressions are used inside the values of the User-Agent
	// sub-attributes of the Proxy's Match attribute. Then compile the
	// configured regexp once and place their respective pointers inside a
	// slice of pointers. Here the index is used to append values to the Config
	// structure and not to the local copy of the for loop.
	for i, p := range config.Proxy {
		// overwrite 'internal' below Config struct members to avoid security
		// issues with possibly untrusted pointers and precompiled regexp
		// passed as input from the configuration file.
		config.Proxy[i].Match._reUserAgent = []*regexp.Regexp{}
		config.Proxy[i].Match._userAgent = []string{""}
		for _, ua := range p.Match.UserAgent {
			if (len(ua) > 0) && (ua[0] == 0x7E) {
				rePtr, err := regexp.Compile(ua[1:])
				if err == nil {
					config.Proxy[i].Match._reUserAgent =
						append(config.Proxy[i].Match._reUserAgent, rePtr)
				}
			} else {
				config.Proxy[i].Match._userAgent =
					append(config.Proxy[i].Match._userAgent, ua)
			}
		}
	}
}
