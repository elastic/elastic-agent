package utils

import "errors"

var ErrNoKeys = errors.New("no key provided")
var ErrKeyNotFound = errors.New("key not found")
var ErrValueNotMap = errors.New("value is not a map")

// GetNestedMap is a utility function to traverse nested maps using a series of key
func GetNestedMap[K comparable](src map[K]any, keys ...K) (any, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if _, ok := src[keys[0]]; !ok {
		// no key found
		return nil, ErrKeyNotFound
	}

	if len(keys) == 1 {
		// we reached the final key, return the value
		return src[keys[0]], nil
	}

	// we have more keys to go through
	valueMap, ok := src[keys[0]].(map[K]any)
	if !ok {
		return nil, ErrValueNotMap
	}

	return GetNestedMap[K](valueMap, keys[1:]...)
}
