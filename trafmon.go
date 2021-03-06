// Copyright 2018 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// afpacket provides a simple example of using afpacket with zero-copy to read
// packet data.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	//	"encoding/binary"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"

	"github.com/spf13/viper"

	_ "github.com/google/gopacket/layers"

	"github.com/influxdata/influxdb1-client/v2"
)

var (
	bufferSize      int
	snapLen         int
	verbose         int = 1000000
	monitorInterval int
	statsInterval   int
	ifaces          []string
	influxHost      string
	influxUser      string
	influxPass      string
	influxDB        string
	influxNameTag   string
	lastReportTime  time.Time
)

var (
	cntPacketsTotal    uint64
	cntPacketsParsed   uint64
	cntPacketsUpload   uint64
	cntPacketsDownload uint64
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
	addr      string
	bytesUp   uint16
	bytesDown uint16
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

	defer afpacket.Close()

	err = afpacket.SetBPF(bpf)
	if err != nil {
		log.Fatal(err)
	}

	myNetsString := [2]string{"10.107.0.0/16", "89.248.240.0/20"}

	var myNets [2]net.IPNet
	for id, myNetString := range myNetsString {
		_, mn, _ := net.ParseCIDR(myNetString)
		myNets[id] = *mn
	}

	// This is needed to skip first ~second of receive, because BPF rules application takes some time...
	initialTimer := time.NewTimer(time.Second)
	skip := true

	//	bytes := uint64(0)
	//	packets := uint64(0)
	for {
		data, _, err := afpacket.ZeroCopyReadPacketData()
		if err != nil {
			log.Fatal(err)
		}

		// skip until one second passes
		if skip == true {
			select {
			case <-initialTimer.C:
				skip = false
			default:
			}
			continue
		}

		atomic.AddUint64(&cntPacketsTotal, 1)

		ethernet := layers.Ethernet{}
		ip := layers.IPv4{}

		err = ethernet.DecodeFromBytes(data, gopacket.NilDecodeFeedback)

		if err != nil {
			log.Printf("Failed to deserialize ethernet layer: %v", err)
			continue
		}

		err = ip.DecodeFromBytes(ethernet.Payload, gopacket.NilDecodeFeedback)

		if err != nil {
			log.Printf("Failed to deserialize ip layer: %v", err)
			continue
		}

		atomic.AddUint64(&cntPacketsParsed, 1)

		for _, myNet := range myNets {
			// Upload
			if myNet.Contains(ip.SrcIP) {
				atomic.AddUint64(&cntPacketsUpload, 1)
				traffic <- flow{ip.SrcIP.String(), uint16(len(data)), 0}
			}
			// Donwload
			if myNet.Contains(ip.DstIP) {
				atomic.AddUint64(&cntPacketsDownload, 1)
				traffic <- flow{ip.DstIP.String(), 0, uint16(len(data))}
			}

		}

		//bytes += uint64(len(data))
		//packets++
		/*	if *count%*verbose == 0 {
			_, afpacketStats, err := afpacket.SocketStats()
			if err != nil {
				log.Println(err)
			}
			log.Printf("%s Read in %d bytes in %d packets", iface, bytes, packets)
			log.Printf("Stats {received dropped queue-freeze}: %d", afpacketStats)
		}*/
	}
	done <- true
}

type counterValue struct {
	bytesUp   uint64
	bytesDown uint64
}

func saveTraffic(m *map[string]counterValue) {
	timeSpent := time.Since(lastReportTime).Seconds()
	lastReportTime = time.Now()

	// Connect to InfluxDB
	influx, err := client.NewHTTPClient(client.HTTPConfig{
		Addr:     influxHost,
		Username: influxUser,
		Password: influxPass,
	})

	if err != nil {
		log.Printf("Error creating InfluxDB Client: %v", err)
		return
	}

	defer influx.Close()

	// Create a new point batch
	bp, _ := client.NewBatchPoints(client.BatchPointsConfig{
		Database:  influxDB,
		Precision: "s",
	})

	log.Printf("Writing buffer to InfluxDB, %d ips", len(*m))

	if len(*m) < 100000 {
		timeInfluxStart := time.Now()
		for ipstring, counter := range *m {
			// Create a point and add to batch
			tags := map[string]string{
				"ip":        ipstring,
				"collector": influxNameTag,
			}

			fields := map[string]interface{}{
				"up":   float64(counter.bytesUp) / timeSpent,
				"down": float64(counter.bytesDown) / timeSpent,
			}

			pt, err := client.NewPoint("traffic", tags, fields, time.Now())
			if err != nil {
				log.Printf("Error creating point: %v", err.Error())
			}

			bp.AddPoint(pt)
		}

		err = influx.Write(bp)

		timeInfluxTaken := time.Since(timeInfluxStart).Seconds()

		if err != nil {
			log.Fatalf("Error writing points: %v", err)
		}

		log.Printf("Written! (took %.2f sec)", timeInfluxTaken)
	} else {
		log.Printf("Got too many points, skipping!")
	}

	*m = make(map[string]counterValue)
}

func handleConfig() {
	viper.SetConfigName("trafmon") // name of config file (without extension)
	viper.SetConfigType("yaml")    // REQUIRED if the config file does not have the extension in the name
	viper.AddConfigPath(".")       // optionally look for config in the working directory

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {
		log.Fatalf("Config parsing error: %v", err)
	}

	configOptions := [9]string{
		"bufferSize",
		"monitorInterval",
		"ifaces",
		"snapLen",
		"influxUser",
		"influxPass",
		"influxHost",
		"influxDB",
		"influxNameTag",
	}

	for _, configOption := range configOptions {
		if viper.IsSet(configOption) != true {
			log.Fatalf("Config error: %v option not found", configOption)
		}
	}

	bufferSize = viper.GetInt("bufferSize")
	if bufferSize < 8 || bufferSize > 512 {
		log.Fatal("Config error: Buffer size not valid!")
	}

	monitorInterval = viper.GetInt("monitorInterval")
	if monitorInterval < 2 || monitorInterval > 3600 {
		log.Fatal("Config error: monitoring interval not valid")
	}

	statsInterval = viper.GetInt("statsInterval")
	if statsInterval < 2 || statsInterval > 3600 {
		log.Fatal("Config error: statistics interval not valid")
	}

	snapLen = viper.GetInt("snapLen")
	if snapLen < 1 || snapLen > 65535 {
		log.Fatal("Config error: snapLen not valid")
	}

	ifaces = viper.GetStringSlice("ifaces")

	influxUser = viper.GetString("influxUser")
	influxPass = viper.GetString("influxPass")
	influxHost = viper.GetString("influxHost")
	influxDB = viper.GetString("influxDB")
	influxNameTag = viper.GetString("influxNameTag")
}

func clearStats() {
	atomic.StoreUint64(&cntPacketsTotal, 0)
	atomic.StoreUint64(&cntPacketsParsed, 0)
	atomic.StoreUint64(&cntPacketsUpload, 0)
	atomic.StoreUint64(&cntPacketsDownload, 0)
}

func printStats() {
	tmpPacketsTotal := atomic.LoadUint64(&cntPacketsTotal)
	tmpPacketsParsed := atomic.LoadUint64(&cntPacketsParsed)
	tmpPacketsUpload := atomic.LoadUint64(&cntPacketsUpload)
	tmpPacketsDownload := atomic.LoadUint64(&cntPacketsDownload)

	log.Printf(
		"Stats - total %v, parsed %v (%.1f %%), upload %v (%.1f %%), download %v (%.1f %%)",
		tmpPacketsTotal,
		tmpPacketsParsed,
		100.0*float32(tmpPacketsParsed)/float32(tmpPacketsTotal),
		tmpPacketsUpload,
		100.0*float32(tmpPacketsUpload)/float32(tmpPacketsParsed),
		tmpPacketsDownload,
		100.0*float32(tmpPacketsDownload)/float32(tmpPacketsParsed),
	)
}

func main() {
	handleConfig()
	clearStats()

	szFrame, szBlock, numBlocks, err := afpacketComputeSize(bufferSize, snapLen, os.Getpagesize())
	if err != nil {
		log.Fatal(err)
	}

	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, snapLen, "ip")
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

	for _, iface := range ifaces {
		log.Printf("Starting capturing thread for %v", iface)
		go runSocket(szFrame, szBlock, numBlocks, iface, bpfIns, traffic, done)
	}

	lastReportTime = time.Now()
	ticker := time.NewTicker(time.Duration(monitorInterval) * time.Second)
	statsTicker := time.NewTicker(time.Duration(statsInterval) * time.Second)

	for {
		select {
		case <-ticker.C:
			if activeCounter {
				go saveTraffic(&counter1)
			} else {
				go saveTraffic(&counter2)
			}

			activeCounter = !activeCounter

		case <-statsTicker.C:
			printStats()
			clearStats()

		case t := <-traffic:

			ipstring := t.addr

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

	<-done
	<-done
}
