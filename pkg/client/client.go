package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/IpsoVeritas/crypto"
	"github.com/IpsoVeritas/logger"
	"github.com/IpsoVeritas/proxy"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"
	jose "gopkg.in/square/go-jose.v1"

	"github.com/IpsoVeritas/document"
)

type ProxyClient struct {
	base        string
	url         string
	endpoint    string
	proxyDomain string
	conn        *websocket.Conn
	writeLock   *sync.Mutex
	regError    error
	regDone     *sync.WaitGroup
	connected   bool
	handler     http.Handler
	key         *jose.JsonWebKey
	lastPing    time.Time
	wg          sync.WaitGroup
	ws          map[string]*wsConn
	wsLock      *sync.Mutex
	stop        bool

	ctx    context.Context
	cancel func()
	lock   *lock
}

func NewProxyClient(endpoint string) (*ProxyClient, error) {
	p := &ProxyClient{
		endpoint: endpoint,
		// proxyDomain: proxyDomain,
		writeLock: &sync.Mutex{},
		lastPing:  time.Now(),
		regDone:   &sync.WaitGroup{},
		wg:        sync.WaitGroup{},
		ws:        make(map[string]*wsConn),
		wsLock:    &sync.Mutex{},
	}
	p.ctx, p.cancel = context.WithCancel(context.Background())
	p.lock = newLock(p.ctx)

	go p.subscribe()

	return p, nil
}

func (p *ProxyClient) connect() error {
	p.lock.Lock()
	defer p.lock.Unlock()

	host := strings.Replace(strings.Replace(p.endpoint, "https://", "", 1), "http://", "", 1)
	schema := "ws"
	if strings.HasPrefix(p.endpoint, "https://") {
		schema = "wss"
	}

	u := url.URL{Scheme: schema, Host: host, Path: "/proxy/subscribe"}

	var err error
	p.conn, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		return err
	}

	// p.connected = true

	p.lastPing = time.Now()

	return nil
}

func (p *ProxyClient) write(b []byte) error {
	p.writeLock.Lock()
	defer p.writeLock.Unlock()

	fmt.Println(string(b))

	if p.conn == nil {
		return errors.New("Not connected")
	}

	return p.conn.WriteMessage(websocket.TextMessage, b)
}

func (p *ProxyClient) Register(key *jose.JsonWebKey) (string, error) {

	if err := p.register(key); err != nil {
		return "", err
	}

	time.Sleep(time.Second * 3)

	return p.base, p.regError

}

func (p *ProxyClient) register(key *jose.JsonWebKey) error {

	// for {
	// 	fmt.Println("waiting to be connected")
	// 	if p.connected {
	// 		break
	// 	}

	// 	time.Sleep(time.Second)
	// }
	p.lock.RLock()
	defer p.lock.RUnlock()

	mandateToken := document.NewMandateToken([]string{}, p.endpoint, 60)

	b, _ := json.Marshal(mandateToken)

	signer, err := crypto.NewSigner(key)
	if err != nil {
		return err
	}

	jws, err := signer.Sign(b)
	if err != nil {
		return err
	}

	jwsCompact, _ := jws.CompactSerialize()

	regReq := proxy.NewRegistrationRequest(jwsCompact)
	regReqBytes, _ := json.Marshal(regReq)

	p.regDone.Add(1)
	if err := p.write(regReqBytes); err != nil {
		return err
	}

	p.regDone.Wait()
	if p.regError != nil {
		return p.regError
	}

	p.key = key
	// p.base = fmt.Sprintf("%s.%s", p.id, p.proxyDomain)

	return nil
}

func (p *ProxyClient) SetHandler(handler http.Handler) {
	p.handler = handler
}

func (p *ProxyClient) Wait() {
	p.wg.Wait()
}

func (p *ProxyClient) disconnect() {
	if p.connected {
		p.conn.Close()
		p.connected = false
	}
	p.stop = true
}

func (p *ProxyClient) ping() {
	for {
		if p.stop {
			return
		}
		// if !p.connected {
		// 	time.Sleep(time.Second)
		// 	continue
		// }
		p.lock.RLock()

		if p.lastPing.Add(time.Second * 20).Before(time.Now()) {
			logger.Warningf("No ping for %2.f seconds", time.Now().Sub(p.lastPing).Seconds())
			p.disconnect()
			time.Sleep(time.Second)
		}
		p.lock.RUnlock()

		time.Sleep(time.Second)
	}
}

func (p *ProxyClient) subscribe() error {
	p.wg.Add(1)
	defer p.wg.Done()

	go p.ping()

	for {
		if p.stop {
			return nil
		}
		if !p.connected {
			fmt.Println("not connected")
			if err := p.connect(); err != nil {
				logger.Error(errors.Wrap(err, "failed to connect to proxy"))
				time.Sleep(time.Second)
				continue
			}

			if p.key != nil {
				fmt.Println("has key")
				go func() {
					if err := p.register(p.key); err != nil {
						logger.Error(errors.Wrap(err, "failed to register to proxy"))
						p.disconnect()
					}
				}()
			}
		}

		_, body, err := p.conn.ReadMessage()
		if err != nil {
			logger.Error(errors.Wrap(err, "failed to read message"))
			p.disconnect()
			time.Sleep(time.Second)
			continue
		}

		fmt.Println(string(body))

		go p.handleMessage(body)
	}
}

func (p *ProxyClient) handleMessage(body []byte) {
	docType, err := document.GetType(body)
	if err != nil {
		logger.Error(errors.Wrap(err, "failed to get document type"))
	}

	switch docType {
	case proxy.SchemaLocation + "/ping.json":
		p.lastPing = time.Now()

	case proxy.SchemaLocation + "/registration-response.json":
		p.lastPing = time.Now()

		r := &proxy.RegistrationResponse{}
		if err := json.Unmarshal(body, &r); err != nil {
			logger.Error(errors.Wrap(err, "failed to unmarshal registration-response"))
			p.regError = err
		}

		if r.Hostname != "" {
			p.base = r.Hostname
		} else {
			p.regError = errors.New("no host in registration-response")
		}

		p.regDone.Done()

	case proxy.SchemaLocation + "/http-request.json":
		p.lastPing = time.Now()

		if p.handler == nil {
			logger.Error("No handler set, can't process http-request")
			return
		}

		req := &proxy.HttpRequest{}
		if err := json.Unmarshal(body, &req); err != nil {
			logger.Error(errors.Wrap(err, "failed to unmarshal http-request"))
			return
		}

		if req != nil {
			r := &http.Request{
				Method: req.Method,
				URL: &url.URL{
					Host:     p.base,
					Path:     req.URL,
					RawQuery: req.Query,
				},
				RequestURI: req.URL,
				Header:     make(http.Header),
				Host:       p.base,
			}

			if req.Headers["X-Forwarded-Host"] != "" {
				r.Host = req.Headers["X-Forwarded-Host"]
			}

			for k, v := range req.Headers {
				r.Header.Set(k, v)
			}

			if req.Body != "" {
				body, err := base64.StdEncoding.DecodeString(req.Body)
				if err == nil {
					r.Body = nopCloser{bytes.NewBuffer(body)}
				} else {
					logger.Error("Failed to decode body")
				}
			}

			w := httptest.NewRecorder()

			p.handler.ServeHTTP(w, r)

			res := proxy.NewHttpResponse(req.ID, w.Result().StatusCode)
			res.ContentType = w.Result().Header.Get("Content-Type")

			body, _ := ioutil.ReadAll(w.Result().Body)
			res.Body = base64.StdEncoding.EncodeToString(body)

			res.Headers = make(map[string]string)
			for k, v := range w.Result().Header {
				res.Headers[k] = v[0]
			}

			b, _ := json.Marshal(res)

			// logger.Debugf("Sending response: %s", b)
			if err := p.write(b); err != nil {
				logger.Error(errors.Wrap(err, "failed to send http-response"))
				p.disconnect()
				return
			}
		}
	}
}

func (p *ProxyClient) Disconnect() error {

	t := proxy.NewDisconnect()
	b, _ := json.Marshal(t)
	p.write(b)

	p.disconnect()
	return nil
}

type nopCloser struct {
	io.Reader
}

func (nopCloser) Close() error {
	return nil
}

type wsConn struct {
	conn *websocket.Conn
	lock *sync.Mutex
}

func (w *wsConn) write(msg []byte) error {
	w.lock.Lock()
	defer w.lock.Unlock()

	return w.conn.WriteMessage(websocket.TextMessage, msg)
}
