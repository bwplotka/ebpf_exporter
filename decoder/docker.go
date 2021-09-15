package decoder

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/cloudflare/ebpf_exporter/config"
)

// DockerContainerIDFromPID is a decoder that transforms process id to docker container ID.
type DockerContainerIDFromPID struct {
	cache map[uint64]string
}

// TODO(bwplotka): Support config.
func (c *DockerContainerIDFromPID) Decode(in []byte, _ config.Decoder) (_ []byte, err error) {
	if c.cache == nil {
		c.cache = map[uint64]string{}
	}

	pid, err := strconv.Atoi(string(in))
	if err != nil {
		return nil, err
	}

	r, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		fmt.Println("error; marking as not-a-docker", err)
		return []byte("not-a-docker-container"), nil

	}
	defer func() {
		if rerr := r.Close(); rerr != nil {
			err = rerr
		}
	}()

	s := bufio.NewScanner(r)
	for s.Scan() {
		text := s.Text()
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 || parts[2] == "/" {
			continue
		}
		if !strings.HasPrefix(parts[2], "/docker/") {
			return []byte("not-a-docker-container"), nil
		}
		cgroup := strings.Split(parts[2], "/")
		containerID := cgroup[len(cgroup)-1]
		return []byte(containerID), nil
	}
	return nil, fmt.Errorf("container ID not found, wrong pid: %v", pid)
}
