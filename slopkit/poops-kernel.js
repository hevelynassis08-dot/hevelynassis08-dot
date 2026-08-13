import { K, TK } from "./poops-common.js?v=final";
import { TWK } from "./poops-twin.js?v=final";

export const PSYS = {
  READ: 0x3,
  WRITE: 0x4,
  OPEN: 0x5,
  CLOSE: 0x6,
  GETPID: 0x14,
  SETUID: 0x17,
  GETUID: 0x18,
  RECVMSG: 0x1b,
  DUP: 0x29,
  FCNTL: 0x5c,
  SOCKET: 0x61,
  NETCONTROL: 0x63,
  SETSOCKOPT: 0x69,
  GETSOCKOPT: 0x76,
  READV: 0x78,
  WRITEV: 0x79,
  SOCKETPAIR: 0x87,
  KQUEUEEX: 0x8d,
  GETRLIMIT: 0xc2,
  SETRLIMIT: 0xc3,
  NANOSLEEP: 0xf0,
  SCHED_YIELD: 0x14b,
  KQUEUE: 0x16a,
  UMTX_OP: 0x1c6,
  THR_NEW: 0x1c7,
  THR_EXIT: 0x1af,
  RTPRIO_THREAD: 0x1d2,
  CPUSET_GETAFFINITY: 0x1e7,
  CPUSET_SETAFFINITY: 0x1e8,
  MMAP: 0x1dd,
  MUNMAP: 0x49,
  JITSHM_CREATE: 0x215,
  JITSHM_ALIAS: 0x216,
  DYNLIB_DLSYM: 0x24f,
  IOCTL: 0x36,
  PIPE2: 0x2af,
};

export const PK = {
  UCRED_SIZE: K.UCRED_SIZE,

  MSG_IOV_NUM: K.MSG_IOV_NUM,

  UIO_IOV_COUNT: K.UIO_IOV_NUM,
  IOV_SIZE: K.IOV_SIZE,

  UIO_SYSSPACE: 1,
  SIZEOF_UIO: 0x30,

  IOV_THREAD_NUM: TK.IOV_THREAD_NUM,
  UIO_THREAD_NUM: TK.UIO_THREAD_NUM,

  TRIPLEFREE_ATTEMPTS: 96,

  NETCTRL_ATTEMPTS: 8,

  MAX_ROUNDS_TWIN: TWK.MAX_ROUNDS_TWIN,

  MAX_ROUNDS_TRIPLET: TWK.MAX_ROUNDS_TRIPLET,

  FIND_TRIPLET_FAST: TWK.FIND_TRIPLET_FAST,

  IOV_FLUSH_ROUNDS: 32,

  STAGE1_REPAIR_ATTEMPTS: 64,

  STAGE1_REPAIR_TRIES: 12,

  RECLAIM_ROUNDS: 2000,

  KSLOW_ATTEMPTS: 3,

  KQ_ROUNDS: 5000,

  KQ_BATCH: 8,

  STAGE2_ATTEMPTS: 5,

  NET_CONTROL_NETEVENT_SET_QUEUE: 0x20000003,
  NET_CONTROL_NETEVENT_CLEAR_QUEUE: 0x20000007,

  LEAK_SYSCALLS_LO: 1,
  LEAK_SYSCALLS_HI: 1,

  LEAK_SYSCALLS_FINAL: 0xfed,
  LEAK_FD_MAX: 8192,
  LEAK_UNROLL: 512,
  LEAK_CORES: 4,

  POC_ARG_HI: 0x8000,
  POC_ARG_LO: 0,
  EXIT_MARK: 0xdead,

  R_ESTIMATE: 69 + 12 + 1 + 1,
  FD_BUDGET_MARGIN: 96,
  FREE_FDS_CAP: 2048,

  FREE_FD_PATHS: [
    "/dev/null",
    "/dev/",
    "/",
    "/app0/",
    "/dev/urandom",
    "/dev/notification0",
    "/dev/gc",
  ],

  OFF: {
    KQ_FDP: 0xa8,

    FILEDESC_OFILES: 0x00,

    FDESCENTTBL_HDR: 0x08,

    FILEDESCENT_SIZE: 0x30,

    FILE_F_DATA: 0x00,

    UIO_IOV: 0x00,
    UIO_IOVCNT: 0x08,
    UIO_OFFSET: 0x10,
    UIO_RESID: 0x18,
    UIO_SEGFLG: 0x20,
    UIO_RW: 0x24,
    UIO_TD: 0x28,

    FILE_F_COUNT: 0x28,

    PIPE_SIGIO: 0xd8,

    SIGIO_PROC: 0x00,

    PROC_PID: 0xbc,


    PROC_UCRED: 0x40,

    UCRED_CR_UID: 0x04,

    SOCKET_SO_PCB: 0x18,

    INPCB_PKTOPTS: 0x120,

    PROC_FD: 0x48,

    UCRED_CR_RUID: 0x08,
    UCRED_CR_SVUID: 0x0c,
    UCRED_CR_NGROUPS: 0x10,
    UCRED_CR_RGID: 0x14,
    UCRED_CR_SVGID: 0x18,

    UCRED_CR_SCEAUTHID: 0x58,
    UCRED_CR_SCECAPS0: 0x60,
    UCRED_CR_SCECAPS1: 0x68,

    UCRED_ATTRS_QWORD: 0x80,

    PROC_DYNLIB: 0x3e8,

    DYNLIB_SC_START: 0xf0,
    DYNLIB_SC_END: 0xf8,

    FD_CDIR: 0x08,

    FD_RDIR: 0x10,
    FD_JDIR: 0x18,

    IP6PO_RTHDR: 0x70,
  },

  PAGE: 0x4000,
  PROT_RWX: 0x7,
  MAP_SHARED: 0x1,

  PROT_RW: 0x3,
  MAP_ANON_PRIVATE: 0x1002,

  LIBKERNEL_HANDLE: 0x2001,

  LIBC_HANDLE: 0x2,



  LK_PTHREAD_CREATE_NAME_NP:
    typeof OFFSET_lk_pthread_create_name_np === "number"
      ? OFFSET_lk_pthread_create_name_np
      : -1,
  LK_PTHREAD_JOIN:
    typeof OFFSET_lk_pthread_join === "number" ? OFFSET_lk_pthread_join : -1,
  LK_SCE_PTHREAD_CREATE:
    typeof OFFSET_lk_scePthreadCreate === "number"
      ? OFFSET_lk_scePthreadCreate
      : -1,
  LK_SCE_PTHREAD_JOIN:
    typeof OFFSET_lk_scePthreadJoin === "number" ? OFFSET_lk_scePthreadJoin : -1,
  LK_SCE_PTHREAD_ATTR_INIT:
    typeof OFFSET_lk_scePthreadAttrInit === "number"
      ? OFFSET_lk_scePthreadAttrInit
      : -1,
  LK_SCE_PTHREAD_ATTR_SETSTACKSIZE:
    typeof OFFSET_lk_scePthreadAttrSetstacksize === "number"
      ? OFFSET_lk_scePthreadAttrSetstacksize
      : -1,
  LK_SCE_PTHREAD_ATTR_SETDETACHSTATE:
    typeof OFFSET_lk_scePthreadAttrSetdetachstate === "number"
      ? OFFSET_lk_scePthreadAttrSetdetachstate
      : -1,
  LK_SCE_PTHREAD_ATTR_DESTROY:
    typeof OFFSET_lk_scePthreadAttrDestroy === "number"
      ? OFFSET_lk_scePthreadAttrDestroy
      : -1,
  LK_NOTIFY: typeof OFFSET_lk_sceKernelSendNotificationRequest === "number"
    ? OFFSET_lk_sceKernelSendNotificationRequest : -1,
  LK_SYSCTLBYNAME: typeof OFFSET_lk_sysctlbyname === "number"
    ? OFFSET_lk_sysctlbyname : -1,
  LK_PTHREAD_CREATE: typeof OFFSET_lk_pthread_create === "number"
    ? OFFSET_lk_pthread_create : -1,
  LK_GETPID: typeof OFFSET_lk_getpid === "number" ? OFFSET_lk_getpid : -1,
  LC_MALLOC: typeof OFFSET_lc_malloc === "number" ? OFFSET_lc_malloc : -1,
  LC_FREE: typeof OFFSET_lc_free === "number" ? OFFSET_lc_free : -1,
  LC_MEMCPY: typeof OFFSET_lc_memcpy === "number" ? OFFSET_lc_memcpy : -1,
  LC_MEMSET: typeof OFFSET_lc_memset === "number" ? OFFSET_lc_memset : -1,
  LC_STRCMP: typeof OFFSET_lc_strcmp === "number" ? OFFSET_lc_strcmp : -1,
  LC_MEMCMP: typeof OFFSET_lc_memcmp === "number" ? OFFSET_lc_memcmp : -1,
  LC_VSNPRINTF: typeof OFFSET_lc_vsnprintf === "number"
    ? OFFSET_lc_vsnprintf : -1,


  STAGE5_SPAWN: "pthread",

  STAGE5_THR_STACK: 0x8000,
  STAGE5_THR_TLS: 0x40,

  STAGE5_WAIT_TICKS: 24,
  STAGE5_WAIT_MS: 250,

  PIPEBUF_SIZE: 0x18,

  PIPE_PAGE_SIZE: 0x4000,

  F_SETOWN: 6,

  FIOSETOWN: 0x8004667c,

  SYSTEM_AUTHID_LO: 0x00010003,
  SYSTEM_AUTHID_HI: 0x48000000,


  SYSCORE_AUTHID_LO: 0x00000007,
  SYSCORE_AUTHID_HI: 0x48000000,

  KERNEL_PID: 0,

  INIT_WALK_MAX: 500,

  KREAD_RETRIES: 3,

  FIONREAD: 0x4004667f,

  KQ_SIGNATURE: 0x1430000,

  KQ_MIN_OUTLEN: 0xb0,

  SIGNAL_DEADLINE_MS: 5000,
  WAIT_DEADLINE_MS: 15000,
  EXIT_DEADLINE_MS: 15000,
  READY_DEADLINE_MS: 8000,

  SETTLE_AFTER_BANK_MS: 500,

  ATTEMPT_GAP_MS: 10,
  SUCCESS_SETTLE_MS: 500,

  STAGE2_SLEEP_SHORT_MS: 100,
  STAGE2_SLEEP_MS: 500,
};

const M1LO = 0xffffffff,
  M1HI = 0xffffffff;

export function isKernelPtr(v) {
  return v !== null && v !== undefined && v.hi >>> 16 === 0xffff;
}

export function isAligned8(v) {
  return v !== null && (v.low & 7) === 0;
}
export function isZero64(v) {
  return v !== null && v.low === 0 && v.hi === 0;
}
export function hx(v) {
  if (v === null || v === undefined) return "null";
  return (
    "0x" +
    (v.hi >>> 0).toString(16) +
    (v.low >>> 0).toString(16).padStart(8, "0")
  );
}

