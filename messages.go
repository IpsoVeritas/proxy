package proxy

import (
	"time"

	document "github.com/IpsoVeritas/document"
	uuid "github.com/satori/go.uuid"
)

const SchemaLocation = document.SchemaBase + "/proxy/v0"

type HttpRequest struct {
	document.Base
	URL     string            `json:"url"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers"`
	Method  string            `json:"method"`
	Body    string            `json:"body"`
}

func NewHttpRequest(url string) *HttpRequest {
	return &HttpRequest{
		Base: document.Base{
			ID:        uuid.NewV4().String(),
			Type:      SchemaLocation + "/http-request.json",
			Timestamp: time.Now().UTC(),
		},
		URL: url,
	}
}

type HttpResponse struct {
	document.Base
	Headers     map[string]string `json:"headers"`
	ContentType string            `json:"contentType"`
	Status      int               `json:"status"`
	Body        string            `json:"body"`
}

func NewHttpResponse(id string, status int) *HttpResponse {
	return &HttpResponse{
		Base: document.Base{
			ID:        id,
			Type:      SchemaLocation + "/http-response.json",
			Timestamp: time.Now().UTC(),
		},
		Status: status,
	}
}

type RegistrationRequest struct {
	document.Base
	MandateToken string `json:"mandateToken"`
	Session      string `json:"session,omitempty"`
}

func NewRegistrationRequest(mandateToken string) *RegistrationRequest {
	return &RegistrationRequest{
		Base: document.Base{
			ID:        uuid.NewV4().String(),
			Type:      SchemaLocation + "/registration-request.json",
			Timestamp: time.Now().UTC(),
		},
		MandateToken: mandateToken,
	}
}

type RegistrationResponse struct {
	document.Base
	KeyID    string `json:"keyID"`
	Hostname string `json:"hostname,omitempty"`
}

func NewRegistrationResponse(id string, keyID string) *RegistrationResponse {
	return &RegistrationResponse{
		Base: document.Base{
			ID:        id,
			Type:      SchemaLocation + "/registration-response.json",
			Timestamp: time.Now().UTC(),
		},
		KeyID: keyID,
	}
}

type Ping struct {
	document.Base
}

func NewPing() *Ping {
	return &Ping{
		Base: document.Base{
			ID:        uuid.NewV4().String(),
			Type:      SchemaLocation + "/ping.json",
			Timestamp: time.Now().UTC(),
		},
	}
}

type WSRequest struct {
	document.Base
	URL     string            `json:"url"`
	Query   string            `json:"query,omitempty"`
	Headers map[string]string `json:"headers"`
}

func NewWSRequest(url string) *WSRequest {
	return &WSRequest{
		Base: document.Base{
			ID:        uuid.NewV4().String(),
			Type:      SchemaLocation + "/ws-request.json",
			Timestamp: time.Now().UTC(),
		},
		URL:     url,
		Headers: make(map[string]string),
	}
}

type WSResponse struct {
	document.Base
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func NewWSResponse(id string, ok bool) *WSResponse {
	return &WSResponse{
		Base: document.Base{
			ID:        id,
			Type:      SchemaLocation + "/ws-response.json",
			Timestamp: time.Now().UTC(),
		},
		OK: ok,
	}
}

type WSMessage struct {
	document.Base
	MessageType int    `json:"messageType"`
	Body        string `json:"body"`
}

func NewWSMessage(id string) *WSMessage {
	return &WSMessage{
		Base: document.Base{
			ID:        id,
			Type:      SchemaLocation + "/ws-message.json",
			Timestamp: time.Now().UTC(),
		},
	}
}

type WSTeardown struct {
	document.Base
}

func NewWSTeardown(id string) *WSTeardown {
	return &WSTeardown{
		Base: document.Base{
			ID:        id,
			Type:      SchemaLocation + "/ws-teardown.json",
			Timestamp: time.Now().UTC(),
		},
	}
}

type Disconnect struct {
	document.Base
}

func NewDisconnect() *Disconnect {
	return &Disconnect{
		Base: document.Base{
			ID:        uuid.NewV4().String(),
			Type:      SchemaLocation + "/disconnect.json",
			Timestamp: time.Now().UTC(),
		},
	}
}
