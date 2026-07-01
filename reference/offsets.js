/*
 * offsets.js — Kernel offsets & constants extracted from p2jb.js
 * 
 * These are REUSABLE across any PS5 exploit targeting FW 9.00–12.40.
 * They describe kernel structure layouts, not vulnerability-specific data.
 */

// ============================================================
// Firmware-specific kernel data segment offsets
// These change per firmware version
// ============================================================
const FW_OFFSETS = {
    "9.00": {
        DATA_BASE_ALLPROC:          0x02755D50n,
        DATA_BASE_SECURITY_FLAGS:   0x00D72064n,
        DATA_BASE_KERNEL_PMAP_STORE:0x02D28B78n,
        DATA_BASE_GVMSPACE:         0x02D8A570n,
    },
    "9.05": {
        DATA_BASE_ALLPROC:          0x02755D50n,
        DATA_BASE_SECURITY_FLAGS:   0x00D73064n,
        DATA_BASE_KERNEL_PMAP_STORE:0x02D28B78n,
        DATA_BASE_GVMSPACE:         0x02D8A570n,
    },
    "10.00": {
        DATA_BASE_ALLPROC:          0x02765D70n,
        DATA_BASE_SECURITY_FLAGS:   0x00D79064n,
        DATA_BASE_KERNEL_PMAP_STORE:0x02CF0EF8n,
        DATA_BASE_GVMSPACE:         0x02D52570n,
    },
    "11.00": {
        DATA_BASE_ALLPROC:          0x02875D70n,
        DATA_BASE_SECURITY_FLAGS:   0x00D8C064n,
        DATA_BASE_KERNEL_PMAP_STORE:0x02E04F18n,
        DATA_BASE_GVMSPACE:         0x02E66570n,
    },
    "12.00": {
        DATA_BASE_ALLPROC:          0x02885E00n,
        DATA_BASE_SECURITY_FLAGS:   0x00D83064n,
        DATA_BASE_KERNEL_PMAP_STORE:0x02E1CFB8n,
        DATA_BASE_GVMSPACE:         0x02E7E570n,
    },
};

// FW version aliases (minor versions share offsets with their major)
const FW_ALIASES = {
    "9.00": "9.00",
    "9.20": "9.05", "9.40": "9.05", "9.60": "9.05",
    "10.00":"10.00","10.01":"10.00","10.20":"10.00","10.40":"10.00","10.60":"10.00",
    "11.00":"11.00","11.20":"11.00","11.40":"11.00","11.60":"11.00",
    "12.00":"12.00","12.02":"12.00","12.20":"12.00","12.40":"12.00",
    "12.60":"12.00","12.70":"12.00",
};

// ============================================================
// Kernel structure field offsets (stable across FW 9.00–12.40)
// These describe FreeBSD kernel struct layouts on PS5
// ============================================================
const KERNEL_STRUCT_OFFSETS = {
    // --- struct proc ---
    PROC_LIST_NEXT:     0x00n,   // LIST_ENTRY(proc) - next proc
    PROC_LIST_PREV:     0x08n,   // LIST_ENTRY(proc) - prev proc
    PROC_THREADS:       0x10n,   // TAILQ_HEAD - first thread
    PROC_UCRED:         0x40n,   // struct ucred *p_ucred
    PROC_FD:            0x48n,   // struct filedesc *p_fd
    PROC_PID:           0xBCn,   // pid_t p_pid
    PROC_VM_SPACE:      0x200n,  // struct vmspace *p_vmspace
    PROC_DYNLIB:        0x3E8n,  // dynlib info pointer

    // --- struct ucred ---
    UCRED_CR_REF:       0x00n,   // u_int cr_ref (THE counter p2jb overflows)
    UCRED_CR_UID:       0x04n,   // uid_t cr_uid
    UCRED_CR_RUID:      0x08n,   // uid_t cr_ruid
    UCRED_CR_SVUID:     0x0Cn,   // uid_t cr_svuid
    UCRED_CR_NGROUPS:   0x10n,   // int cr_ngroups
    UCRED_CR_RGID:      0x14n,   // gid_t cr_rgid
    UCRED_CR_SVGID:     0x18n,   // gid_t cr_svgid
    UCRED_CR_SCEAUTHID: 0x58n,   // uint64_t (Sony-specific)
    UCRED_CR_SCECAPS0:  0x60n,   // uint64_t (Sony capability bits 0)
    UCRED_CR_SCECAPS1:  0x68n,   // uint64_t (Sony capability bits 1)
    UCRED_CR_ATTRS:     0x80n,   // ucred attributes

    // --- struct filedesc ---
    FILEDESC_OFILES:    0x00n,   // struct fdescenttbl *fd_ofiles
    FD_CDIR:            0x08n,   // struct vnode *fd_cdir (current dir)
    FD_RDIR:            0x10n,   // struct vnode *fd_rdir (root dir)
    FD_JDIR:            0x18n,   // struct vnode *fd_jdir (jail dir)

    // --- struct fdescenttbl ---
    FDESCENTTBL_HDR:    0x08n,   // header offset to fd entries
    FILEDESCENT_SIZE:   0x30n,   // sizeof(struct filedescent)

    // --- struct socket ---
    SO_PCB:             0x18n,   // struct inpcb *so_pcb

    // --- struct inpcb (IPv6) ---
    INPCB_PKTOPTS:      0x120n,  // struct ip6_pktopts *
    IP6PO_RTHDR:        0x70n,   // routing header option offset

    // --- struct pipe ---
    PIPE_SIGIO:         0xD8n,   // struct sigio *pipe_sigio

    // --- struct kqueue ---
    KQ_FDP:             0xA8n,   // struct filedesc *kq_fdp

    // --- pmap (page table) ---
    PMAP_PML4:          0x20n,   // PML4 virtual address
    PMAP_CR3:           0x28n,   // CR3 physical address

    // --- GPU virtual memory ---
    SIZEOF_GVMSPACE:    0x100n,
    GVMSPACE_START_VA:  0x08n,
    GVMSPACE_SIZE:      0x10n,
    GVMSPACE_PAGE_DIR_VA: 0x38n,

    // --- thread ---
    TD_PROC:            0x08n,   // struct proc *td_proc
    TD_NEXT:            0x10n,   // next thread in list
    TD_UCRED:           0x140n,  // struct ucred *td_ucred
};

// ============================================================
// System constants
// ============================================================
const SYSTEM_CONSTANTS = {
    SYSTEM_AUTHID:      0x4800000000010003n,  // Sony system auth ID
    PAGE_SIZE:          0x4000,                // PS5 page size (16KB)
    UCRED_SIZE:         360,                   // sizeof(struct ucred)
};

// ============================================================
// Syscall numbers (PS5 FreeBSD kernel)
// ============================================================
const SYSCALL_NUMS = {
    read:               0x03n,
    write:              0x04n,
    open:               0x05n,
    close:              0x06n,
    socket:             0x61n,
    setsockopt:         0x69n,
    getsockopt:         0x76n,
    recvmsg:            0x1Bn,
    socketpair:         0x87n,
    fcntl:              0x5Cn,
    mmap:               0xDDn,
    mprotect:           0x4An,
    ioctl:              0x36n,
    kqueue:             0x16An,
    kqueueex:           0x8Dn,
    readv:              0x78n,
    writev:             0x79n,
    getpid:             0x14n,
    setuid:             0x17n,
    setrlimit:          0xC3n,
    sched_yield:        0x14Bn,
    nanosleep:          0xF0n,
    cpuset_setaffinity: 0x00n, // via SYSCALL table
    cpuset_getaffinity: 0x00n, // via SYSCALL table
    rtprio_thread:      0x00n, // via SYSCALL table
    thr_exit:           0x1F1n,
    umtx_op:            0x1C6n,
    jitshm_create:      0x00n, // Sony-specific
    jitshm_alias:       0x00n, // Sony-specific
};

// ============================================================
// Socket constants
// ============================================================
const SOCKET_CONSTANTS = {
    AF_UNIX:        1n,
    AF_INET6:       28n,
    SOCK_STREAM:    1n,
    IPPROTO_IPV6:   41n,
    IPV6_RTHDR:     51n,
    SOL_SOCKET:     0xFFFFn,
    SO_SNDBUF:      0x1001n,
};

// ============================================================
// Jailbreak values (what to write for privilege escalation)
// ============================================================
const JAILBREAK_VALUES = {
    // Set all these on proc_ucred to become root + unjailed:
    CR_UID:         0,          // root uid
    CR_RUID:        0,          // root real uid
    CR_SVUID:       0,          // root saved uid
    CR_NGROUPS:     1,          // single group
    CR_RGID:        0,          // root group
    CR_SVGID:       0,          // root saved group
    CR_SCEAUTHID:   0x4800000000010003n,  // system auth
    CR_SCECAPS0:    0xFFFFFFFFFFFFFFFFn,  // all capabilities
    CR_SCECAPS1:    0xFFFFFFFFFFFFFFFFn,  // all capabilities
    CR_ATTRS_MASK:  0x80n,      // attribute flag to OR in at offset +0x80

    // Debug menu flags:
    SECURITY_FLAGS_OR:  0x14n,
    TARGET_ID_SET:      0x82n,
    QA_FLAGS_OR:        0x10300n,
    UTOKEN_FLAGS_OR:    0x1n,
};
