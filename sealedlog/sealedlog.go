package sealedlog

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/mirkobrombin/atomloops/internal/sealedlog"
)

var (
	ErrUnknownComponent = errors.New("sealedlog: unknown component")
	ErrUnknownEvent     = errors.New("sealedlog: unknown event")
)

var dictionary sync.Once

func loadDictionary(path string) {
	dictionary.Do(func() {
		if b, err := os.ReadFile(path); err == nil {
			_ = sealedlog.LoadDictionary(b)
		}
	})
}

type Writer struct {
	component sealedlog.Component
	socket    string
}

func Open(component string) (*Writer, error) {
	return OpenAt(component, sealedlog.DefaultDictionary, sealedlog.DefaultSocket)
}

func OpenAt(component, dictionaryPath, socket string) (*Writer, error) {
	loadDictionary(dictionaryPath)
	c, ok := sealedlog.ComponentByName(component)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrUnknownComponent, component)
	}
	return &Writer{component: c, socket: socket}, nil
}

func (w *Writer) Log(event string, args ...uint64) error {
	if w == nil {
		return nil
	}
	code, ok := sealedlog.CodeByName(w.component, event)
	if !ok {
		return fmt.Errorf("%w: %s for %s", ErrUnknownEvent, event, w.component)
	}
	if len(args) > sealedlog.MaxArgs {
		args = args[:sealedlog.MaxArgs]
	}
	return sealedlog.Emit(w.socket, sealedlog.Record{Component: w.component, Code: code, Args: args})
}
