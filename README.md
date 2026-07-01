# 🚀 LetsGo — Fast PS5 Jailbreak Exploit

**Goal:** Build a PS5 kernel exploit that runs in **under 1 minute**, replacing the 47-minute p2jb kqueueex exhaustion approach.

**Target firmware:** 9.00 – 12.40 (same as p2jb)

**Status:** Research & Development

## Project Structure

```
letsgo/
├── README.md               ← You are here
├── docs/
│   ├── discoveries.md      ← Research findings & discoveries log
│   ├── p2jb_analysis.md    ← What we extracted from p2jb
│   └── exploit_research.md ← Known fast PS5 exploits & techniques
├── reference/
│   ├── offsets.js           ← Kernel offsets extracted from p2jb
│   └── primitives.js       ← Reusable kernel r/w primitives from p2jb
└── exploit/
    └── fast_jb.js           ← The new exploit (when ready)
```

## Why p2jb Is Slow

p2jb uses a `kqueueex` cr_ref overflow that requires ~4.29 billion syscalls (~47 min on 4 cores).
The overflow is needed to create a use-after-free condition for the initial kernel primitive.

## Our Approach

Find or adapt a **faster initial primitive** that achieves the same UAF condition without
billions of syscalls, then reuse p2jb's proven stages 1-7 for kernel r/w and jailbreak.
