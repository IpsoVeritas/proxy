package client

import (
	"context"
	"sync"

	"github.com/pkg/errors"
)

var (
	errLockContextClosed = errors.New("Lock context closed")
)

type lock struct {
	c   chan struct{}
	wg  *sync.WaitGroup
	ctx context.Context
}

func newLock(ctx context.Context) *lock {
	l := &lock{
		c:   make(chan struct{}, 1),
		wg:  &sync.WaitGroup{},
		ctx: ctx,
	}
	l.Unlock()

	return l
}

func (l *lock) Lock() error {
	select {
	case <-l.ctx.Done():
		return errLockContextClosed
	case <-l.c:
		l.wg.Wait()
		return nil
	}
}

func (l *lock) Unlock() {
	l.c <- struct{}{}
}

func (l *lock) RLock() error {
	if err := l.Lock(); err != nil {
		return err
	}
	l.wg.Add(1)
	l.Unlock()

	return nil
}

func (l *lock) RUnlock() {
	l.wg.Done()
}
