package db

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"vue-project-backend/internal/config"
)

// OpenRedis creates a Redis client from config. Password is optional.
func OpenRedis(cfg config.Config) (*redis.Client, error) {
	client := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       0,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping: %w", err)
	}
	return client, nil
}
