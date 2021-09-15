package decoder

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/iovisor/gobpf/bcc"
	"golang.org/x/sys/unix"
)

// CGroup is a decoder that transforms cgroup id to path in cgroupfs
type CGroup struct {
	cache map[uint64]string
}

// Decode transforms cgroup id to path in cgroupfs
func (c *CGroup) Decode(in []byte, _ config.Decoder) ([]byte, error) {
	if c.cache == nil {
		c.cache = map[uint64]string{}
	}

	cgroupID, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	if path, ok := c.cache[uint64(cgroupID)]; ok {
		return []byte(path), nil
	}

	if err := c.refreshCache(); err != nil {
		log.Printf("Error refreshing cgroup id to path map: %s", err)
		if path, ok := c.cache[uint64(cgroupID)]; ok {
			// Cache unknown result on successful refresh.
			return []byte(path), nil
		}
		return []byte(fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)), nil
	}

	if _, ok := c.cache[uint64(cgroupID)]; !ok {
		// Cache unknown result on successful refresh.
		c.cache[uint64(cgroupID)] = fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)
	}

	return []byte(c.cache[uint64(cgroupID)]), nil
}

func (c *CGroup) refreshCache() error {
	byteOrder := bcc.GetHostByteOrder()

	newCache := make(map[uint64]string, len(c.cache)) // Reset cache.
	if err := filepath.Walk("/sys/fs/cgroup", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			return nil
		}

		handle, _, err := unix.NameToHandleAt(unix.AT_FDCWD, path, 0)
		if err != nil {
			log.Printf("Error resolving handle of %s: %s", path, err)
			return nil
		}
		newCache[byteOrder.Uint64(handle.Bytes())] = path
		return nil
	}); err != nil {
		// Update cache on error cases, to have at least partial results.
		for k, v := range newCache {
			c.cache[k] = v
		}
		return err
	}
	c.cache = newCache
	log.Println("refreshed cgroup cache, keys: ", len(c.cache))
	return nil
}
