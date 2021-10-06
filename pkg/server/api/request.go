package api

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/IpsoVeritas/logger"
	"github.com/IpsoVeritas/proxy"
	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"
	"github.com/ulule/limiter"
)

type RequestController struct {
	domain  string
	clients proxy.Registry
	limiter *limiter.Limiter
}

func NewRequestController(domain string, clients proxy.Registry, limiter *limiter.Limiter) *RequestController {
	return &RequestController{
		domain:  domain,
		clients: clients,
		limiter: limiter,
	}
}

func (s *RequestController) Handle(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	clientID := params.ByName("clientID")

	// If domain is set and the request was for a host that has our domain as suffix we will strip away the domain and use the rest as the clientID
	if s.domain != "" {
		host := r.Host
		if strings.HasSuffix(host, "."+s.domain) {
			clientID = strings.Replace(host, "."+s.domain, "", 1)
		}
	}

	client, err := s.clients.Get(clientID)
	if err != nil {
		http.Error(w, errors.Wrap(err, "failed to get client").Error(), http.StatusBadGateway)
		return
	}

	limit, err := s.limiter.Get(r.Context(), clientID)
	if err != nil {
		http.Error(w, errors.Wrap(err, "failed to get limit").Error(), http.StatusInternalServerError)
		return
	}

	if limit.Reached {
		http.Error(w, "Too many requests", http.StatusTooManyRequests)
		return
	}

	msg := proxy.NewHttpRequest(params.ByName("filepath"))
	msg.Headers = make(map[string]string)
	msg.Query = r.URL.RawQuery
	for k, v := range r.Header {
		msg.Headers[k] = v[0]
	}
	msg.Method = r.Method

	data, err := ioutil.ReadAll(io.LimitReader(r.Body, 1024*500))
	if err == nil {
		if err := r.Body.Close(); err != nil {
			http.Error(w, errors.Wrap(err, "failed to close body").Error(), http.StatusInternalServerError)
			return
		}
		msg.Body = base64.StdEncoding.EncodeToString(data)
	}

	cr, cw := io.Pipe()
	c := &requestClient{
		Writer: cw,
		id:     msg.ID,
	}
	if err := s.clients.Register(c); err != nil {
		logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	body, _ := json.Marshal(msg)
	if _, err := client.Write(body); err != nil {
		logger.Error(err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	resp := &proxy.HttpResponse{}
	if err := json.NewDecoder(cr).Decode(&resp); err != nil {
		logger.Error(errors.Wrap(err, "failed to unmarshal response"))
		http.Error(w, errors.Wrap(err, "failed to unmarshal response").Error(), http.StatusInternalServerError)
		return
	}

	respBody, err := base64.StdEncoding.DecodeString(resp.Body)
	if err != nil {
		logger.Error(errors.Wrap(err, "failed to decode response body"))
		http.Error(w, errors.Wrap(err, "failed to decode response body").Error(), http.StatusInternalServerError)
		return
	}

	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}

	w.WriteHeader(resp.Status)
	w.Write(respBody)

}

type requestClient struct {
	io.Writer
	id string
}

func (c *requestClient) ID() string {
	return c.id
}
