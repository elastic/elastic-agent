package vault

import "context"

type Vault interface {
	Exists(ctx context.Context, key string) (bool, error)
	Get(ctx context.Context, key string) (dec []byte, err error)
	Set(ctx context.Context, key string, data []byte) (err error)
	Remove(ctx context.Context, key string) (err error)
	Close() error
}
