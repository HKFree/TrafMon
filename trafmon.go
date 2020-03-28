// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// afpacket provides a simple example of using afpacket with zero-copy to read
// packet data.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"net"
//	"encoding/binary"
	"time"
//	"runtime/pprof"
//	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	_ "github.com/google/gopacket/layers"
)

var (
	iface      = flag.String("i", "any", "Interface to read from")
	cpuprofile = flag.String("cpuprofile", "", "If non-empty, write CPU profile here")
	snaplen    = flag.Int("s", 0, "Snaplen, if <= 0, use 65535")
	bufferSize = flag.Int("b", 8, "Interface buffersize (MB)")
	filter     = flag.String("f", "port not 22", "BPF filter")
	count      = flag.Int64("c", -1, "If >= 0, # of packets to capture before returning")
	verbose    = flag.Int64("log_every", 1, "Write a log every X packets")
	addVLAN    = flag.Bool("add_vlan", false, "If true, add VLAN header")
)

// afpacketComputeSize computes the block_size and the num_blocks in such a way that the
// allocated mmap buffer is close to but smaller than target_size_mb.
// The restriction is that the block_size must be divisible by both the
// frame size and page size.
func afpacketComputeSize(targetSizeMb int, snaplen int, pageSize int) (
	frameSize int, blockSize int, numBlocks int, err error) {

	if snaplen < pageSize {
		frameSize = pageSize / (pageSize / snaplen)
	} else {
		frameSize = (snaplen/pageSize + 1) * pageSize
	}

	// 128 is the default from the gopacket library so just use that
	blockSize = frameSize * 128
	numBlocks = (targetSizeMb * 1024 * 1024) / blockSize

	if numBlocks == 0 {
		return 0, 0, 0, fmt.Errorf("Interface buffersize is too small")
	}

	return frameSize, blockSize, numBlocks, nil
}

type flow struct {
	addr		net.IP
	bytesUp		uint16
	bytesDown	uint16
}

func runSocket(szFrame int, szBlock int, numBlocks int, iface string, bpf []bpf.RawInstruction, traffic chan flow, done chan bool) {
	afpacket, err := afpacket.NewTPacket(
			afpacket.OptInterface(iface),
                        afpacket.OptFrameSize(szFrame),
                        afpacket.OptBlockSize(szBlock),
                        afpacket.OptNumBlocks(numBlocks),
                        afpacket.OptAddVLANHeader(false),
                        afpacket.OptPollTimeout(pcap.BlockForever),
                        afpacket.SocketRaw,
                        afpacket.TPacketVersion3)

	if err != nil {
		log.Fatal(err)
	}

//	source := gopacket.ZeroCopyPacketDataSource(afpacket)
	defer afpacket.Close()

	err = afpacket.SetBPF(bpf)
	if err != nil {
		log.Fatal(err)
	}

	myNetsString := [2]string{"10.107.0.0/16", "89.248.240.0/20"}

	var myNets [2]net.IPNet
	for id, myNetString := range myNetsString{
		_, mn, _ := net.ParseCIDR(myNetString)
		myNets[id] = *mn
	}

	bytes := uint64(0)
	packets := uint64(0)
	for ; *count != 0; *count-- {
		data, _, err := afpacket.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}

		ethernet := layers.Ethernet{}
		ip := layers.IPv4{}

		err = ethernet.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

		if err != nil {
			log.Fatalf("Failed to deserialize ethernet layer: %v", err)
		}

		err = ip.DecodeFromBytes(ethernet.Payload, gopacket.NilDecodeFeedback)

		if err != nil {
			log.Fatal("Failed to deserialize ip layer: %v", err)
		}

		// Upload
		for _, myNet := range myNets {
			if myNet.Contains(ip.SrcIP) {
				traffic<-flow{ip.SrcIP, uint16(len(data)), 0}
			}
		}

		// Donwload
		for _, myNet := range myNets {
			if myNet.Contains(ip.DstIP) {
				traffic<-flow{ip.DstIP, 0, uint16(len(data))}
			}
		}


		bytes += uint64(len(data))
		packets++
		if *count%*verbose == 0 {
			_, afpacketStats, err := afpacket.SocketStats()
			if err != nil {
				log.Println(err)
			}
			log.Printf("%s Read in %d bytes in %d packets", iface, bytes, packets)
			log.Printf("Stats {received dropped queue-freeze}: %d", afpacketStats)
		}
	}
	done <- true
}

type counterValue struct {
	bytesUp		uint64
	bytesDown 	uint64
}


func saveTraffic(m *map[string]counterValue) {
//	log.Print(*m)
	log.Print("Flushing buffer")
	*m =  make(map[string]counterValue)
}

func main() {
	flag.Parse()

	log.Printf("Starting on interface %q", *iface)

	if *snaplen <= 0 {
		*snaplen = 65535
	}

	szFrame, szBlock, numBlocks, err := afpacketComputeSize(*bufferSize, *snaplen, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}

	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, *snaplen, "ip")
	if err != nil {
		log.Fatal(err)
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}

	counter1 := make(map[string]counterValue)
	counter2 := make(map[string]counterValue)
	activeCounter := true

	done := make(chan bool, 2)
	traffic := make(chan flow, 100000)

	go runSocket(szFrame, szBlock, numBlocks, "eth4", bpfIns, traffic, done)
	go runSocket(szFrame, szBlock, numBlocks, "eth5", bpfIns, traffic, done)

	ticker := time.NewTicker(5 * time.Second)

	for {
		select {
		case <-ticker.C:
			if activeCounter {
				go saveTraffic(&counter1)
//				log.Print(counter1)
//				counter1 = make(map[string]counterValue)
			} else {
				go saveTraffic(&counter2)
//				log.Print(counter2)
//				counter2 = make(map[string]counterValue)
			}

			activeCounter = !activeCounter

		case t := <-traffic:

//			ipuint := binary.BigEndian.Uint32(t.addr)
			ipstring := t.addr.String()

			var m counterValue

			if activeCounter {
				m = counter1[ipstring]
			} else {
				m = counter2[ipstring]
			}

			m.bytesUp += uint64(t.bytesUp)
			m.bytesDown += uint64(t.bytesDown)

                        if activeCounter {
				counter1[ipstring] = m
			} else {
				counter2[ipstring] = m
			}
		}
	}

	<- done
	<- done
}
