package main

import (
	"log"

	"golang.org/x/net/context"

	"golang.org/x/crypto/acme/autocert"
)

type debugCache struct {
	u autocert.Cache
}

func newDebugCache(u autocert.Cache) autocert.Cache {
	return debugCache{u: u}
}

func (c debugCache) Get(ctx context.Context, key string) ([]byte, error) {
	res, err := c.u.Get(ctx, key)
	log.Print("DEBUG: get ", key)
	if err != nil {
		log.Print("Cache Get debug: ", err)
	}
	return res, err
}

func (c debugCache) Put(ctx context.Context, key string, data []byte) error {
	err := c.u.Put(ctx, key, data)
	log.Print("DEBUG: put ", key)
	if err != nil {
		log.Print("Cache Put debug: ", err)
	}
	return err
}

func (c debugCache) Delete(ctx context.Context, key string) error {
	err := c.u.Delete(ctx, key)
	log.Print("DEBUG: delete ", key)
	if err != nil {
		log.Print("Cache Delete debug: ", err)
	}
	return err
}
