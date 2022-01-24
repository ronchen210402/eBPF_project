#!/usr/bin/env python3

from bcc import BPF
import time

device = "lo" #boris: We attach our XDP filter onto the lo interface. (loopback)
ebpfProgram = BPF(src_file="filter.c")
fn = ebpfProgram.load_func("xdpfilter", BPF.XDP)
ebpfProgram.attach_xdp(device, fn, 0)

try:
  ebpfProgram.trace_print()
except KeyboardInterrupt:
  pass

ebpfProgram.remove_xdp(device, 0)

