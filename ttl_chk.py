#!/usr/bin/env python

from bcc import BPF
import ctypes as ct
import socket
import json
import struct
import logging
import sys
import commands

def get_logger():
    logger = logging.getLogger("ttl")
    if not logger.handlers:
        handler = logging.StreamHandler(stream=sys.stdout)
        formatter = logging.Formatter('[%(asctime)s] [%(process)d] %(filename)s[%(funcName)s] %(levelname)s %(message)s')
        handler.setFormatter(formatter)
        handler.setLevel(logging.INFO)
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger

def pid2netns(pid):
    cmd_run = "ip netns identify " + str(pid)
    status, result = commands.getstatusoutput(cmd_run)
    if status != 0:
        return None
    return result


class TtlMsg(ct.Structure):
    _fields_ = [("in_src", ct.c_uint32),
                ("in_dst", ct.c_uint32),
                ("out_src", ct.c_uint32),
                ("out_dst", ct.c_uint32),
                ("pid", ct.c_uint32)]

def cb(cpu, data, size):
    if size < ct.sizeof(TtlMsg):
        return
    event = ct.cast(data, ct.POINTER(TtlMsg)).contents
    inSrc = socket.inet_ntoa(struct.pack('<L', event.in_src))
    inDst = socket.inet_ntoa(struct.pack('<L', event.in_dst))
    outSrc = socket.inet_ntoa(struct.pack('<L',event.out_src))
    outDst = socket.inet_ntoa(struct.pack('<L',event.out_dst))
    netns = pid2netns(event.pid)
    get_logger().info("netns: %s(%s), in_hdr: %s -> %s, out_hdr: %s->%s", event.pid, netns, inSrc, inDst, outSrc, outDst)


prog = """
#include <net/inet_sock.h>

BPF_PERF_OUTPUT(ttl_event);
BPF_ARRAY(ts, u64, 1);

typedef struct {
    u8   type;
    u8   code;
    u16  chksum;
    u32  pad;
}icmp_hdr_t;

typedef struct {
    u8 ver_ihl;
    u8 tos;
    u16 tot_len;
    u16 id;
    u16 frag_off;
    u8 ttl;
    u8 prot;
    u16 checksum;
    u32 saddr;
    u32 daddr;
} ip_hdr_t;

typedef struct {
    u16 sport;
    u16 dport;
    u16 len;
    u16 chksum;
} udp_hdr_t;

typedef struct {
    u32 in_src;
    u32 in_dst;
    u32 out_src;
    u32 out_dst;
    u32 pid;
} ttl_event_t;

#define PROT_ICMP 1
#define PROT_UDP 17
#define DPORT_TRACEROUTE 53
#define ICMP_TTL_EXPIRED 11

// report 1 ttl expired event per second at most
#define MIN_INTERVAL 1000000

static int chk_ttl(struct pt_regs *ctx,struct sk_buff *skb){
    u64 now;
    unsigned char *hdr_ = skb->head + skb->network_header;
    ip_hdr_t *out_ip = (ip_hdr_t*)hdr_;
    if (out_ip->prot == PROT_ICMP) {
        hdr_ += sizeof(ip_hdr_t);
        icmp_hdr_t *icmp = (icmp_hdr_t*)hdr_;
        if (icmp->type == ICMP_TTL_EXPIRED) {
            hdr_ += sizeof(icmp_hdr_t);
            ip_hdr_t *in_ip = (ip_hdr_t*)hdr_;
            if (in_ip->prot == PROT_UDP) {
                hdr_ += sizeof(ip_hdr_t);
                udp_hdr_t *udp = (udp_hdr_t*)(hdr_);
                if (udp->dport==htons(DPORT_TRACEROUTE))
                    return 0;
            }
            now = bpf_ktime_get_ns();
            int zero = 0;
            u64 *last_ts = ts.lookup(&zero);
            if (!last_ts)
                return 0;
            if ((now-*last_ts) < MIN_INTERVAL) {
                return 0;
            }
            *last_ts = now;
            ttl_event_t event;
            event.in_src = in_ip->saddr;
            event.in_dst = in_ip->daddr;
            event.out_src = out_ip->saddr;
            event.out_dst = out_ip->daddr;
            event.pid = bpf_get_current_pid_tgid();
            ttl_event.perf_submit(ctx, &event, sizeof(event));
        }
    }
    return 0;
}
int kprobe__ip_rcv(struct pt_regs *ctx,struct sk_buff *skb){
    return chk_ttl(ctx, skb);
}
int kprobe__ip_forward(struct pt_regs *ctx,struct sk_buff *skb){
    return chk_ttl(ctx, skb);
}
"""
b = BPF(text=prog)
b["ttl_event"].open_perf_buffer(cb)

while True:
    b.kprobe_poll()
