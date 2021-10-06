package clients

import (
	"sync"

	"github.com/IpsoVeritas/proxy"
)

type Registry struct {
	clients map[string]proxy.Client
	lock    *sync.RWMutex
}

func New() *Registry {
	return &Registry{
		clients: make(map[string]proxy.Client),
		lock:    &sync.RWMutex{},
	}
}

func (c *Registry) Get(id string) (proxy.Client, error) {
	c.lock.RLock()
	defer c.lock.RUnlock()

	client, ok := c.clients[id]
	if !ok {
		return nil, proxy.ErrClientNotFound
	}

	return client, nil
}

func (c *Registry) Register(client proxy.Client) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	c.clients[client.ID()] = client

	return nil
}

func (c *Registry) Unregister(client proxy.Client) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	delete(c.clients, client.ID())

	return nil
}
