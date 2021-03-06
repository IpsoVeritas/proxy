package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/IpsoVeritas/crypto"
	"github.com/IpsoVeritas/logger"
	"github.com/IpsoVeritas/proxy/pkg/client"
	"github.com/joho/godotenv"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v1"
)

func main() {
	_ = godotenv.Load(".env")
	viper.AutomaticEnv()
	viper.SetDefault("log_formatter", "text")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("local", "http://localhost:8080")
	viper.SetDefault("local_url", "")
	viper.SetDefault("proxy_endpoint", "https://proxy.svc.integrity.app")
	viper.SetDefault("key", "./proxy-client.pem")
	viper.SetDefault("state", "")

	logger.SetOutput(os.Stdout)
	logger.SetFormatter(viper.GetString("log_formatter"))
	logger.SetLevel(viper.GetString("log_level"))

	var key *jose.JsonWebKey
	_, err := os.Stat(viper.GetString("key"))
	if err != nil {
		key, err = crypto.NewKey()
		if err != nil {
			logger.Fatal(err)
		}

		kb, err := crypto.MarshalToPEM(key)
		if err != nil {
			logger.Fatal(err)
		}

		if err := ioutil.WriteFile(viper.GetString("key"), kb, 0600); err != nil {
			logger.Fatal(err)
		}
	} else {
		kb, err := ioutil.ReadFile(viper.GetString("key"))
		if err != nil {
			logger.Fatal(err)
		}

		key, err = crypto.UnmarshalPEM(kb)
		if err != nil {
			logger.Fatal(err)
		}
	}

	p, err := client.NewProxyClient(viper.GetString("proxy_endpoint"))
	if err != nil {
		logger.Fatal(err)
	}

	hostname, err := p.Register(key)
	if err != nil {
		logger.Fatal(err)
	}

	logger.Infof("Got hostname: %s", hostname)

	p.SetHandler(&httpClient{})

	if viper.GetString("state") != "" {
		s := state{
			Hostname: hostname,
		}

		sb, err := json.Marshal(s)
		if err != nil {
			logger.Fatal(err)
		}

		if err := ioutil.WriteFile(viper.GetString("state"), sb, 0600); err != nil {
			logger.Fatalf("Failed to write state file: %s", err)
		}
	}

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Println()
		fmt.Println(sig)
		p.Disconnect()
	}()

	p.Wait()
}

type state struct {
	Hostname string `json:"hostname"`
}

type httpClient struct{}

func (h *httpClient) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if r.URL.RawQuery != "" {
		path = fmt.Sprintf("%s?%s", path, r.URL.RawQuery)
	}

	logger.Debugf("Request for %s%s", r.Host, path)

	req, err := http.NewRequest(r.Method, fmt.Sprintf("%s%s", viper.GetString("local"), path), r.Body)
	if err != nil {
		logger.Error(err)
		return
	}

	for k, v := range r.Header {
		switch strings.ToUpper(k) {
		case "DNT":
			continue
		case "UPGRADE-INSECURE-REQUESTS":
			continue
		default:
			req.Header.Set(k, v[0])
		}
	}
	if viper.GetString("local_url") != "" {
		req.Header.Set("Host", viper.GetString("local_url"))
	} else {
		req.Header.Set("Host", r.Host)
	}

	client := &http.Client{
		Timeout: time.Second * 15,
	}

	res, err := client.Do(req)
	if err != nil {
		logger.Error(err)
		return
	}

	for k, v := range res.Header {
		w.Header().Set(k, v[0])
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		logger.Error(err)
		return
	}

	w.Write(body)

	w.WriteHeader(res.StatusCode)
}
