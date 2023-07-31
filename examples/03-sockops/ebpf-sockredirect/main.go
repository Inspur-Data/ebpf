// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"os"
	"os/signal"
	"syscall"
	"encoding/binary"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)


// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags $BPF_CFLAGS bpf bpf_redir.c -- -I../../headers
func main() {
	
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	fmt.Printf("interface name:%s\n", ifaceName)
	//ifaceName := "ens47f1"
	
	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects failed: %v", err)
	}
	defer objs.Close()
	
}

