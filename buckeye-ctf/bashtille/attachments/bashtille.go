package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"time"
)

func handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	dir := "/app/jails/" + randomHex(16)

	cmd := exec.CommandContext(ctx, "/proc/self/exe", "child", dir)
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: 0,
				HostID:      1000,
				Size:        1,
			},
		},
		Unshareflags: syscall.CLONE_NEWNS,
	}

	_ = cmd.Run()

	os.RemoveAll(dir)
}

func main() {
	switch os.Args[1] {
	case "server":
		server()
	case "child":
		child(os.Args[2])
	default:
		panic("help")
	}
}

func server() {
	listener, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatal("Failed to start server:", err)
	}
	defer listener.Close()

	log.Println("Listening on port 5000...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println("Connection error:", err)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		go func() {
			defer cancel()
			defer runtime.GC()
			handleConnection(ctx, conn)
		}()
	}
}

func copy(src string, dst string) {
	data, err := os.ReadFile(src)
	must(err)
	must(os.WriteFile(dst, data, 0755))
}

func child(dir string) {
	must(syscall.Mkdir(dir, 0700))
	must(syscall.Mkdir(dir+"/bin", 0700))
	must(syscall.Mkdir(dir+"/lib", 0700))
	must(syscall.Mkdir(dir+"/lib/x86_64-linux-gnu", 0700))
	must(syscall.Mkdir(dir+"/lib64", 0700))

	copy("/bin/bash", dir+"/bin/bash")
	copy("/lib/x86_64-linux-gnu/libtinfo.so.6", dir+"/lib/x86_64-linux-gnu/libtinfo.so.6")
	copy("/lib/x86_64-linux-gnu/libc.so.6", dir+"/lib/x86_64-linux-gnu/libc.so.6")
	copy("/lib64/ld-linux-x86-64.so.2", dir+"/lib64/ld-linux-x86-64.so.2")

	must(syscall.Chroot(dir))

	must(os.Chdir("/"))

	cmd := exec.Command("/bin/bash", "-i")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	_ = cmd.Run()
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, err := rand.Read(bytes)
	must(err)
	return hex.EncodeToString(bytes)
}
