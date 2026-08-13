// @egycnq (I rewrote egys impli of poops but 90% of his code is likely still factored in)

export const ERRNO = {
  1: "EPERM",
  2: "ENOENT",
  3: "ESRCH",
  4: "EINTR",
  5: "EIO",
  6: "ENXIO",
  7: "E2BIG",
  8: "ENOEXEC",
  9: "EBADF",
  10: "ECHILD",
  11: "EDEADLK",
  12: "ENOMEM",
  13: "EACCES",
  14: "EFAULT",
  15: "ENOTBLK",
  16: "EBUSY",
  17: "EEXIST",
  18: "EXDEV",
  19: "ENODEV",
  20: "ENOTDIR",
  21: "EISDIR",
  22: "EINVAL",
  23: "ENFILE",
  24: "EMFILE",
  25: "ENOTTY",
  26: "ETXTBSY",
  27: "EFBIG",
  28: "ENOSPC",
  29: "ESPIPE",
  30: "EROFS",
  31: "EMLINK",
  32: "EPIPE",
  33: "EDOM",
  34: "ERANGE",
  35: "EAGAIN",
  36: "EINPROGRESS",
  37: "EALREADY",
  38: "ENOTSOCK",
  39: "EDESTADDRREQ",
  40: "EMSGSIZE",
  41: "EPROTOTYPE",
  42: "ENOPROTOOPT",
  43: "EPROTONOSUPPORT",
  44: "ESOCKTNOSUPPORT",
  45: "EOPNOTSUPP",
  46: "EPFNOSUPPORT",
  47: "EAFNOSUPPORT",
  48: "EADDRINUSE",
  49: "EADDRNOTAVAIL",
  50: "ENETDOWN",
  51: "ENETUNREACH",
  52: "ENETRESET",
  53: "ECONNABORTED",
  54: "ECONNRESET",
  55: "ENOBUFS",
  56: "EISCONN",
  57: "ENOTCONN",
  58: "ESHUTDOWN",
  59: "ETOOMANYREFS",
  60: "ETIMEDOUT",
  61: "ECONNREFUSED",
  62: "ELOOP",
  63: "ENAMETOOLONG",
  65: "EHOSTUNREACH",
  66: "ENOTEMPTY",
  69: "EDQUOT",
  78: "ENOSYS",
  84: "EOVERFLOW",
  89: "ECAPMODE",
  90: "ENOTCAPABLE",
  91: "EINTEGRITY",
};

export const K = {
  AF_UNIX: 1,
  AF_INET: 2,
  AF_INET6: 28,
  SOCK_STREAM: 1,
  SOCK_DGRAM: 2,
  IPPROTO_IPV6: 41,

  SOL_SOCKET: 0xffff,
  SO_SNDBUF: 0x1001,
  IPV6_RTHDR: 51,
  IPV6_RTHDR_TYPE_0: 0,

  RTHDR_TAG: 0x13370000,

  UCRED_SIZE: 0x168,

  IOV_SIZE: 0x10,
  MSG_IOV_NUM: 0x17,
  UIO_IOV_NUM: 0x14,

  F_GETFL: 3,
  F_SETFL: 4,
  O_NONBLOCK: 4,
  O_RDONLY: 0,

  SEEK_SET: 0,
  SEEK_END: 2,

  FIOSETOWN: 0x8004667c,

  PROT_READ: 0x1,
  PROT_WRITE: 0x2,
  MAP_PRIVATE: 0x2,
  MAP_ANONYMOUS: 0x1000,

  CPU_LEVEL_WHICH: 3,
  CPU_WHICH_TID: 1,
  CPUSET_SIZE: 0x10,
  RTP_LOOKUP: 0,
  RTP_SET: 1,

  UMTX_OP_WAIT: 2,
  UMTX_OP_WAKE: 3,

  AMD64_GET_FSBASE: 128,

  MSG_DONTWAIT: 0x80,
};

const SK = K;

export const BANNED = {
  0x02a: "sys_compat10.pipe -- legacy ABI, returns fd1 in RDX",
};

export function buildRthdr(u8, off, size) {
  const len = ((size >> 3) - 1) & ~1;
  u8[off + 0] = 0;
  u8[off + 1] = len & 0xff;
  u8[off + 2] = K.IPV6_RTHDR_TYPE_0;
  u8[off + 3] = (len >> 1) & 0xff;
  return (len + 1) << 3;
}

export function w16(u8, o, v) {
  u8[o] = v & 0xff;
  u8[o + 1] = (v >>> 8) & 0xff;
}
export function w32(u8, o, v) {
  u8[o] = v & 0xff;
  u8[o + 1] = (v >>> 8) & 0xff;
  u8[o + 2] = (v >>> 16) & 0xff;
  u8[o + 3] = (v >>> 24) & 0xff;
}
export function r16(u8, o) {
  return (u8[o] | (u8[o + 1] << 8)) >>> 0;
}
export function r32(u8, o) {
  return (
    (u8[o] | (u8[o + 1] << 8) | (u8[o + 2] << 16) | (u8[o + 3] << 24)) >>> 0
  );
}

export function w64(u8, o, v) {
  if (v !== null && typeof v === "object") {
    w32(u8, o, v.low);
    w32(u8, o + 4, v.hi);
  } else {
    w32(u8, o, v >>> 0);
    w32(u8, o + 4, Math.floor(v / 0x100000000) >>> 0);
  }
}
export function coreList(mask) {
  const out = [];
  for (let i = 0; i < 32; ++i) if ((mask >>> i) & 1) out.push(i);
  return out.join(",");
}

export function hexBytes(u8, off, n) {
  let s = "";
  for (let i = 0; i < n; ++i)
    s += (i ? " " : "") + u8[off + i].toString(16).padStart(2, "0");
  return s;
}

export const TK = {
  CPU_LEVEL_WHICH: SK.CPU_LEVEL_WHICH,
  CPU_WHICH_TID: SK.CPU_WHICH_TID,
  CPUSET_SIZE: SK.CPUSET_SIZE,
  RTP_LOOKUP: SK.RTP_LOOKUP,
  RTP_SET: SK.RTP_SET,
  UMTX_OP_WAIT: SK.UMTX_OP_WAIT,
  UMTX_OP_WAKE: SK.UMTX_OP_WAKE,

  PRI_REALTIME: 2,
  PRI_TIMESHARE: 3,
  PRI_IDLE: 4,

  POOPS_RTPRIO: 256,

  NWAKE_ALL: 0x7fffffff,

  IOV_THREAD_NUM: 4,
  UIO_THREAD_NUM: 4,

  KPRIM_STANDIN_DEFAULT: 8,
  KPRIM_STANDIN_CAP: 32,

  ST_DEFAULT: 0,
  ST_READY: 1,
  ST_DONE: 2,
  ST_EXITED: 3,
};

export const SYS = {
  READ: 0x3,
  WRITE: 0x4,
  CLOSE: 0x6,
  GETPID: 0x14,
  SOCKET: 0x61,
  NANOSLEEP: 0xf0,
  SCHED_YIELD: 0x14b,
  THR_EXIT: 0x1af,
  THR_SELF: 0x1b0,
  THR_KILL: 0x1b1,
  UMTX_OP: 0x1c6,
  THR_NEW: 0x1c7,
  RTPRIO_THREAD: 0x1d2,
  CPUSET_GETAFFINITY: 0x1e7,
  CPUSET_SETAFFINITY: 0x1e8,
  PIPE2: 0x2af,
  THR_SUSPEND_UCONTEXT: 0x278,
  THR_RESUME_UCONTEXT: 0x279,
};
