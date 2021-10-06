package proxy

import (
	"errors"
	"io"
)

var (
	ErrClientNotFound = errors.New("client not found")
)

type Registry interface {
	Register(client Client) error
	Unregister(client Client) error
	Get(id string) (Client, error)
}

type Client interface {
	io.Writer
	ID() string
}
