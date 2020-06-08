# TrafMon
Simple program written in Go, able to listen to traffic on two ports, counting up transferred data, agregating by source/destination IP.

Uses AF_PACKET Linux interface with MMAP, resulting in zero-copy packet processing. In current state, TrafMon is able to listen to ~10 gbit of small packets with only minor cpu/irq load! 

Only supported output is InfluxDB, however extension to other database is straightforward.
