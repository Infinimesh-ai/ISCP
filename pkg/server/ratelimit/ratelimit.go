package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	counters map[string]counter
}

type counter struct {
	count int
	reset time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{limit: limit, window: window, counters: map[string]counter{}}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	c := l.counters[key]
	if c.reset.IsZero() || now.After(c.reset) {
		c = counter{reset: now.Add(l.window)}
	}
	if c.count >= l.limit {
		l.counters[key] = c
		return false
	}
	c.count++
	l.counters[key] = c
	return true
}
