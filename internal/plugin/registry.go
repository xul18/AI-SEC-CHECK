package plugin

import (
	"fmt"
	"sync"
)

type Registry struct {
	mu      sync.RWMutex
	plugins map[string]ScannerPlugin
}

var globalRegistry = &Registry{
	plugins: make(map[string]ScannerPlugin),
}

func GlobalRegistry() *Registry {
	return globalRegistry
}

func NewRegistry() *Registry {
	return &Registry{
		plugins: make(map[string]ScannerPlugin),
	}
}

func (r *Registry) Register(p ScannerPlugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := p.Name()
	if _, exists := r.plugins[name]; exists {
		return fmt.Errorf("plugin %q already registered", name)
	}
	r.plugins[name] = p
	return nil
}

func (r *Registry) Get(name string) (ScannerPlugin, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plugins[name]
	return p, ok
}

func (r *Registry) List() []ScannerPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ScannerPlugin, 0, len(r.plugins))
	for _, p := range r.plugins {
		result = append(result, p)
	}
	return result
}

func (r *Registry) ListByCategory(category string) []ScannerPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ScannerPlugin, 0)
	for _, p := range r.plugins {
		if p.Category() == category {
			result = append(result, p)
		}
	}
	return result
}

func (r *Registry) AvailablePlugins() []ScannerPlugin {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]ScannerPlugin, 0)
	for _, p := range r.plugins {
		if p.IsAvailable() {
			result = append(result, p)
		}
	}
	return result
}

func Register(p ScannerPlugin) error {
	return globalRegistry.Register(p)
}

func GetPlugin(name string) (ScannerPlugin, bool) {
	return globalRegistry.Get(name)
}

func ListPlugins() []ScannerPlugin {
	return globalRegistry.List()
}

func ListPluginsByCategory(category string) []ScannerPlugin {
	return globalRegistry.ListByCategory(category)
}
