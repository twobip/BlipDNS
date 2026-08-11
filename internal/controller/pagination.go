package controller

import (
	"net/http"
	"strconv"
	"time"
)

const maxPageOffset = 1_000_000

func boundedLimit(r *http.Request, fallback, maximum int) int {
	value := fallback
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < 1 {
		return fallback
	}
	if value > maximum {
		return maximum
	}
	return value
}

func boundedOffset(r *http.Request) int {
	raw := r.URL.Query().Get("offset")
	if raw == "" {
		return 0
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 0 {
		return 0
	}
	if value > maxPageOffset {
		return maxPageOffset
	}
	return value
}

func boundedDuration(r *http.Request, key string, fallback, minimum, maximum time.Duration) time.Duration {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil || value < minimum || value > maximum {
		return fallback
	}
	return value
}
