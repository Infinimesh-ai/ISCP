package replay

import (
	"sync"
	"time"
)

type Cache struct {
	mu    sync.Mutex
	items map[string]time.Time
}

func NewCache() *Cache {
	return &Cache{items: map[string]time.Time{}}
}

func (c *Cache) Use(key string, expiresAt time.Time, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, exp := range c.items {
		if now.After(exp) {
			delete(c.items, k)
		}
	}
	if exp, ok := c.items[key]; ok && now.Before(exp) {
		return false
	}
	c.items[key] = expiresAt
	return true
}
