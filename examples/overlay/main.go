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
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 -cflags $BPF_CFLAGS bpf overlay.c -- -I../headers
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
	

	// Attach the program.
	qdisc,err := attachProgram(ifaceName,objs.bpfPrograms.TcPrint)
	if err != nil{
		log.Fatalf("attach program failed: %v", err)
	}

	
	//get interfaces on the host
	ifs , err := net.Interfaces()
	if err!= nil{
		log.Fatalf("get interface failed:%v", err)
	}

	//put the index to ebpfMap
	for _, interf := range ifs{
		addres , er := interf.Addrs()
		if er != nil{
			log.Printf("get interface:%s address failed:%v", interf.Name,er)
			continue
		}
		for _,addre := range addres{
			//get the ip "192.168.1.1/32"
			tempaddrestr := addre.String()
			addrestrs := strings.Split(tempaddrestr,"/")
			//addrestr = "192.168.1.1"
			addrestr := addrestrs[0]
			tempIP := net.ParseIP(addrestr)
			intIP,err := ipv4ToInt(tempIP)
			if err != nil{
				fmt.Printf("convert IP:%s, to int failed:%v\n",addrestr,err )
				continue
			}
			//convert the ip to bigint
			fmt.Printf("ip:%s,intIP:%d,ifindex:%d\n",addrestr,intIP,interf.Index)
			err = objs.IfindexMap.Put(intIP, uint32(interf.Index))
			if err != nil{
				fmt.Printf("put map failed:%v,key:%d,value:%d\n", err,intIP,interf.Index)
			}
		} 

	}

	var quit chan os.Signal  
	quit = make(chan os.Signal, 1)  
	// set signal channel
	c := make(chan os.Signal, 1)  
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)  
	go func() {  
	for {  
			<-c  
			fmt.Println("Received SIGINT, gracefully shutting down...")  
			//tc filter del dev qdisc  
			netlink.QdiscDel(qdisc)
			objs.Close()
			close(quit)  
		}  
	}()  
	
	<-quit  
	fmt.Println("Exiting...")  
}

func attachProgram(ifaceName string, program *ebpf.Program) (*netlink.GenericQdisc, error) {
	devID, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil,fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return nil,fmt.Errorf("could not get replace qdisc: %w", err)
	}
	

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return nil, fmt.Errorf("failed to replace tc filter: %w", err)
	}
	return qdisc,nil
}

func ipv4ToInt(ipaddr net.IP) (uint32, error) {
	if ipaddr.To4() == nil {
		return 0, fmt.Errorf("the address %s is not an ipv4 address\n", ipaddr)
	}
	return binary.LittleEndian.Uint32(ipaddr.To4()), nil
	//return uint(binary.LittleEndian.Uint32(ipaddr.To4())), nil
}