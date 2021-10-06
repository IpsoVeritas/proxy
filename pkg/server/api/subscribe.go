package api

import (
	"context"
	hash "crypto"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IpsoVeritas/crypto"
	"github.com/IpsoVeritas/document"
	"github.com/IpsoVeritas/httphandler"
	"github.com/IpsoVeritas/logger"
	"github.com/IpsoVeritas/proxy"
	"github.com/gorilla/websocket"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	uuid "github.com/satori/go.uuid"
	"github.com/spf13/viper"
	jose "gopkg.in/square/go-jose.v1"
)

type SubscribeController struct {
	domain  string
	clients proxy.Registry
}

func NewSubscribeController(domain string, clients proxy.Registry) *SubscribeController {
	return &SubscribeController{
		domain:  domain,
		clients: clients,
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func (s *SubscribeController) SubscribeHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx := context.WithValue(r.Context(), httphandler.RequestIDKey, uuid.NewV4().String())
	log := logger.ForContext(ctx)

	respHeaders := make(http.Header)
	respHeaders.Add("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	conn, err := upgrader.Upgrade(w, r, respHeaders)
	if err != nil {
		http.Error(w, errors.Wrap(err, "failed to upgrade to websocket").Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	client := s.newClient(r.Context(), conn)

	if err := client.handle(); err != nil {
		log.Error(err)
	}

	log.Debug("Client disconnected")
}

type client struct {
	clients proxy.Registry
	domain  string

	ctx    context.Context
	cancel func()

	lock *sync.Mutex
	conn *websocket.Conn
	wg   *sync.WaitGroup

	authenticated chan bool
	id            string

	logger *logger.Entry
}

func (s *SubscribeController) newClient(ctx context.Context, conn *websocket.Conn) *client {
	c := &client{
		clients:       s.clients,
		domain:        s.domain,
		lock:          &sync.Mutex{},
		conn:          conn,
		wg:            &sync.WaitGroup{},
		logger:        httphandler.LoggerForContext(ctx),
		authenticated: make(chan bool),
	}

	c.ctx, c.cancel = context.WithCancel(ctx)

	go func(c *client) {
		select {
		case <-ctx.Done():
			return
		case <-c.authenticated:
			c.logger.Debug("Client authenticated")
			return
		case <-time.After(time.Second * 10):
			c.logger.Warn("Not authenticated after 10 seconds, dropping connection")
			c.cancel()
		}
	}(c)

	return c
}

func (c *client) ID() string {
	return c.id
}

func (c *client) Write(p []byte) (n int, err error) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if err = c.conn.WriteMessage(websocket.TextMessage, p); err != nil {
		return 0, err
	}

	return len(p), nil
}

func (c *client) handle() error {
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Debug("context done")
			if err := c.clients.Unregister(c); err != nil {
				c.logger.Error(err)
			}
			c.wg.Wait()
			return nil
		default:
			fmt.Println("read message")
			_, body, err := c.conn.ReadMessage()
			if err != nil {
				return errors.Wrap(err, "failed to read message")
			}

			fmt.Println(string(body))

			c.wg.Add(1)
			go c.handleMessage(body)
		}
	}
}

func (c *client) handleMessage(body []byte) {
	defer c.wg.Done()
	docType, err := document.GetType(body)
	if err != nil {
		c.logger.Error("failed to get type of document: ", err)
		return
	}

	switch docType {
	case proxy.SchemaLocation + "/registration-request.json":
		r := &proxy.RegistrationRequest{}
		if err := json.Unmarshal(body, &r); err != nil {
			c.logger.Error("failed to unmarshal registration-request: ", err)
			return
		}

		if err := c.register(r); err != nil {
			c.logger.Error(err)
			return
		}

	case proxy.SchemaLocation + "/http-response.json":
		r := &proxy.HttpResponse{}
		if len(body) > 1024*500 {
			r.Status = http.StatusBadGateway
		} else {
			if err := json.Unmarshal(body, &r); err != nil {
				c.logger.Error(err)
				return
			}
		}
		if r != nil {
			client, err := c.clients.Get(r.ID)
			if err != nil {
				c.logger.Error(err)
				return
			}
			if _, err := client.Write(body); err != nil {
				c.logger.Error(err)
			}
		}
	case proxy.SchemaLocation + "/disconnect.json":
		c.cancel()
		return

	default:
		c.logger.Warningf("Unknown message type %s", docType)
	}
}

func (c *client) register(r *proxy.RegistrationRequest) error {
	key, err := parseMandateToken(r.MandateToken)
	if err != nil {
		c.Write([]byte(err.Error()))
		return err
	}

	c.id = crypto.Thumbprint(key)
	if r.Session != "" {
		h := hash.SHA256.New()
		h.Write([]byte(c.id))
		h.Write([]byte(r.Session))

		c.id = strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(h.Sum(nil)))
	}

	c.logger.Debugf("Adding client %s", c.id)
	c.authenticated <- true

	if err := c.clients.Register(c); err != nil {
		return errors.Wrap(err, "failed to register client")
	}

	res := proxy.NewRegistrationResponse(r.ID, c.id)
	if c.domain != "" {
		res.Hostname = fmt.Sprintf("%s.%s", c.id, c.domain)
	}
	resBytes, _ := json.Marshal(res)
	if _, err = c.Write([]byte(resBytes)); err != nil {
		return err
	}

	go c.ping()

	return nil
}

func (c *client) ping() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-time.After(time.Second * 10):
			if _, err := c.Write([]byte(fmt.Sprintf(`{"@type":"%s/ping.json"}`, proxy.SchemaLocation))); err != nil {
				c.logger.Error(err)
				c.cancel()
				return
			}
		}
	}
}

func parseMandateToken(tokenString string) (*jose.JsonWebKey, error) {
	tokenJWS, err := crypto.UnmarshalSignature([]byte(tokenString))
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal JWS")
	}

	if len(tokenJWS.Signatures) < 1 || tokenJWS.Signatures[0].Header.JsonWebKey == nil {
		return nil, errors.New("no jwk in token")
	}

	payload, err := tokenJWS.Verify(tokenJWS.Signatures[0].Header.JsonWebKey)
	if err != nil {
		return nil, errors.Wrap(err, "failed to verify token")
	}

	token := &document.MandateToken{}
	err = json.Unmarshal(payload, &token)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal token")
	}

	if token.Timestamp.Add(time.Second * time.Duration(token.TTL)).Before(time.Now().UTC()) {
		return nil, errors.New("Token has expired")
	}

	if !strings.HasPrefix(token.URI, viper.GetString("base")) {
		return nil, errors.New("Token not for this endpoint")
	}

	return tokenJWS.Signatures[0].Header.JsonWebKey, nil
}
