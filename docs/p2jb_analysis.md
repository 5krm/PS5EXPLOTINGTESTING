# p2jb Analysis — What We Can Reuse

## Architecture of p2jb (2,499 lines)

The exploit has a clear **pipeline architecture**. The critical insight is that only
the FIRST stage (prepare_fds) is slow. Everything after it is fast and REUSABLE.

```
┌─────────────────────────────────────────────────────────────────┐
│                    SLOW PART (47 minutes)                       │
│                                                                 │
│  prepare_fds()  →  4.29B kqueueex calls  →  FD pool created   │
│  Lines 771-903                                                  │
│                                                                 │
│  THIS IS WHAT WE WANT TO REPLACE                                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                    FAST PARTS (< 2 minutes total)               │
│                                                                 │
│  stage0: Triple-free race using FD pool        (~30 sec)       │
│  stage1: Kqueue reclaim → leak proc_filedesc   (~5 sec)        │
│  stage2: Leak pipe kernel pointers             (~10 sec)       │
│  stage3: Corrupt pipe buffer → kernel r/w      (~10 sec)       │
│  stage4: Walk proc list → find rootvnode       (~1 sec)        │
│  stage5: Write ucred → jailbreak               (~1 sec)        │
│  stage6: Resolve kernel data_base              (~1 sec)        │
│  stage7: Patch dynlib restrictions             (~1 sec)        │
│  stage_debug: GPU DMA → enable debug menu      (~2 sec)        │
│  stage_elfldr: Load ELF loader on port 9021    (~2 sec)        │
│                                                                 │
│  ALL OF THESE ARE REUSABLE AS-IS                                │
└─────────────────────────────────────────────────────────────────┘
```

## What prepare_fds() Actually Does (and why)

The kqueueex exhaustion serves ONE purpose: create a pool of file descriptors
whose kernel-internal fd numbers ALIAS with existing objects.

After 2^32+1 kqueueex calls, the kernel's fd counter wraps around. New fd
allocations now get numbers that overlap with previously allocated fds.
This creates CONFUSED KERNEL STATE where two different userspace fds point
to the same kernel object.

Stage0 then exploits this confusion to create overlapping IPv6 socket
allocations (the "triplets"), which give us the ability to read/write
kernel memory through socket options.

## Key Question for Any Replacement

Any alternative to the kqueueex exhaustion must achieve the same result:
**Create overlapping kernel allocations (specifically, two IPv6 socket
option buffers that share the same physical memory).**

Methods that could achieve this:
1. Direct UAF via sys_netcontrol (Poopsploit) — proven, fast
2. Race condition on socket close/reopen — possible but unproven
3. Heap spray + reclaim after a different UAF — needs a new vuln
4. TOCTOU in mmap/munmap — theoretical

## Extracted Components (ready to reuse)

### Files created:
- `reference/offsets.js` — All kernel offsets, struct layouts, FW tables
- `reference/primitives.js` — 7 post-UAF primitives (pipe k/rw, jailbreak, etc.)

### What's NOT extracted (exploit-specific, would need rewriting):
- `prepare_fds()` — The 47-min kqueueex exhaustion (THIS IS WHAT WE REPLACE)
- `stage0 attempt_race()` — Depends on the FD pool from prepare_fds
- `build_leak_worker_chain()` — ROP chains for kqueueex workers
- `find_twins() / find_triplet()` — IPv6 rthdr race (partially reusable)

### What IS directly reusable without modification:
- `build_pipe_krw()` — Pipe-based kernel read/write (stage3)
- `find_curproc()` — SIGIO trick to find proc struct (stage3_cleanup)
- `find_rootvnode()` — Walk proc list (stage4)
- `jailbreak()` — Credential escalation (stage5)
- `resolve_data_base()` — Find kernel data segment (stage6)
- `patch_dynlib()` — Remove dynlib restrictions (stage7)
- `post_jb_stabilize()` — Credential migration (post-jb)
- All GPU DMA code — Debug menu enablement (stage_debug)
- All ELF loader code — stage_load_elf
