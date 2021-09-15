package decoder

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

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
		return []byte(fmt.Sprintf("%s:%d", path, cgroupID)), nil
	}

	// Try find first (faster than looking up all cgroup paths).
	cmd := exec.Command("find", "/sys/fs/cgroup", "-inum", string(in))
	out, err := cmd.Output()
	if err != nil {
		log.Printf("Error finding cgroup path from inode number: %s, falling back to cgroup traverse.", err)
	} else if !strings.HasPrefix(string(out), "/sys/fs/cgroup/") {
		log.Printf("Unexpected find output for cgroup id %v: %s, falling back to cgroup traverse.", string(in), string(out))
	} else {
		path := strings.ReplaceAll(string(out), "\n", "")
		c.cache[uint64(cgroupID)] = path
		return []byte(path), nil
	}

	if err := c.refreshCache(); err != nil {
		log.Printf("Error refreshing cgroup id to path map: %s", err)
	}

	if path, ok := c.cache[uint64(cgroupID)]; ok {
		return []byte(path), nil
	}

	return []byte(fmt.Sprintf("unknown_cgroup_id:%d", cgroupID)), nil
}

func (c *CGroup) refreshCache() error {
	byteOrder := bcc.GetHostByteOrder()

	return filepath.Walk("/sys/fs/cgroup", func(path string, info os.FileInfo, err error) error {
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

		c.cache[byteOrder.Uint64(handle.Bytes())] = path
		return nil
	})
}
