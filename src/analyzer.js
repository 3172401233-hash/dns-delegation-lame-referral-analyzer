/**
 * 权威 DNS 委派分析器（离线快照）。
 *
 * 输入快照（snapshot）结构：
 * {
 *   query: { name, type, dnssec },
 *   zones: {
 *     "example.com": {
 *       referral: {                       // 父区给出的委派信息
 *         ns: ["ns1.example.com", ...],
 *         glue: { "ns1.example.com": { A: [...], AAAA: [...] } },
 *         ds: true | false                // 父区是否带有 DS（DNSSEC）
 *       },
 *       childNS: ["ns1.example.com", ...] // 子区自己权威应答里的 NS 集合
 *     }
 *   },
 *   responses: {
 *     "ns1.example.com": {
 *       "example.com": {
 *         aa: true, rcode: "NOERROR",
 *         supportedTypes: ["A", "AAAA"],   // 该 NS 权威支持的记录类型
 *         dnssecOk: true
 *       }
 *     }
 *   },
 *   addresses: { "ns2.example.net": { A: [...], AAAA: [...] } }, // 区外 NS 的解析结果
 *   cnames: [{ name, zone, target, otherRecords: ["TXT"] }]
 * }
 */

const DELEGATION_BREAK_RCODES = new Set(["REFUSED", "SERVFAIL", "NOTAUTH", "NOTIMP"]);

function normalizeName(name) {
  return String(name).replace(/\.$/, "").toLowerCase();
}

function labelsOf(name) {
  const n = normalizeName(name);
  return n === "" ? [] : n.split(".");
}

function isSubdomainOf(name, zone) {
  const n = normalizeName(name);
  const z = normalizeName(zone);
  return n === z || n.endsWith("." + z);
}

function ancestorZonesOf(name) {
  const labels = labelsOf(name);
  const zones = [];
  for (let i = 1; i <= labels.length; i += 1) {
    zones.push(labels.slice(labels.length - i).join("."));
  }
  return zones;
}

function zoneOfName(name, knownZones) {
  for (const zone of ancestorZonesOf(name)) {
    if (knownZones.has(zone)) return zone;
  }
  return null;
}

function hasAddress(record) {
  return Boolean(record && ((record.A && record.A.length > 0) || (record.AAAA && record.AAAA.length > 0)));
}

function missingFamilies(record) {
  const missing = [];
  if (!record || !record.A || record.A.length === 0) missing.push("A");
  if (!record || !record.AAAA || record.AAAA.length === 0) missing.push("AAAA");
  return missing;
}

/** 构建 NS 解析依赖图并检测循环委派（互相委派且都没有 glue）。 */
function detectCyclicDelegations(zones) {
  const graph = new Map();
  for (const [zoneName, zone] of zones) {
    const deps = new Set();
    for (const ns of zone.referral?.ns ?? []) {
      const nsName = normalizeName(ns);
      const glue = zone.referral?.glue?.[ns] ?? zone.referral?.glue?.[nsName];
      if (hasAddress(glue)) continue; // 有 glue 就不构成外部依赖
      const nsZone = zoneOfName(nsName, new Set(zones.keys()));
      if (nsZone && nsZone !== zoneName) deps.add(nsZone);
    }
    graph.set(zoneName, deps);
  }

  const cycles = [];
  const state = new Map(); // 0=未访问 1=在栈中 2=完成
  const stack = [];
  function visit(node) {
    state.set(node, 1);
    stack.push(node);
    for (const next of graph.get(node) ?? []) {
      const s = state.get(next) ?? 0;
      if (s === 0) {
        visit(next);
      } else if (s === 1) {
        const start = stack.indexOf(next);
        cycles.push([...stack.slice(start), next]);
      }
    }
    stack.pop();
    state.set(node, 2);
  }
  for (const node of graph.keys()) {
    if ((state.get(node) ?? 0) === 0) visit(node);
  }
  return cycles;
}

export function analyzeDelegation(snapshot) {
  const query = {
    name: normalizeName(snapshot.query?.name ?? ""),
    type: String(snapshot.query?.type ?? "A").toUpperCase(),
    dnssec: Boolean(snapshot.query?.dnssec),
  };
  const zoneEntries = Object.entries(snapshot.zones ?? {}).map(([name, zone]) => [normalizeName(name), zone]);
  const zones = new Map(zoneEntries);
  const responses = snapshot.responses ?? {};
  const addresses = snapshot.addresses ?? {};
  const cnames = snapshot.cnames ?? [];

  const issues = [];
  const issueKeys = new Set();
  function addIssue(issue) {
    const key = `${issue.type}|${issue.zone ?? ""}|${issue.ns ?? ""}|${issue.name ?? ""}`;
    if (issueKeys.has(key)) return;
    issueKeys.add(key);
    issues.push(issue);
  }

  // 解析链：从根到目标区，只保留快照中出现的区。
  const chain = ancestorZonesOf(query.name).filter((z) => zones.has(z));

  // 1. 循环委派
  for (const cycle of detectCyclicDelegations(zones)) {
    addIssue({
      type: "cyclic-delegation",
      cycle,
      detail: `委派形成循环：${cycle.join(" -> ")}，且环节上没有可用 glue，无法引导解析`,
    });
  }

  // 2. 逐区检查委派信息
  const nsProblems = new Map(); // `${zone}|${ns}` -> problem
  for (const [zoneName, zone] of zones) {
    const referral = zone.referral ?? {};
    const nsList = (referral.ns ?? []).map(normalizeName);
    const glue = referral.glue ?? {};

    // 委派与子区 NS 不一致
    if (Array.isArray(zone.childNS)) {
      const childSet = new Set(zone.childNS.map(normalizeName));
      const parentSet = new Set(nsList);
      const onlyInParent = [...parentSet].filter((n) => !childSet.has(n));
      const onlyInChild = [...childSet].filter((n) => !parentSet.has(n));
      if (onlyInParent.length > 0 || onlyInChild.length > 0) {
        addIssue({
          type: "delegation-ns-mismatch",
          zone: zoneName,
          onlyInParent,
          onlyInChild,
          detail: "父区委派的 NS 列表与子区权威 NS 记录不一致",
        });
      }
    }

    // DNSSEC：查询要求验证但父区缺少 DS
    if (query.dnssec && referral.ds === false) {
      addIssue({
        type: "dnssec-gap",
        zone: zoneName,
        detail: "查询开启 DNSSEC 验证，但父区委派中没有 DS 记录，验证链断裂",
      });
    }

    for (const ns of nsList) {
      const inBailiwick = isSubdomainOf(ns, zoneName);
      const glueRec = glue[ns] ?? glue[ns.replace(/\.$/, "")];
      const external = addresses[ns];

      if (inBailiwick && !hasAddress(glueRec)) {
        // 区内 NS 必须依赖 glue
        addIssue({
          type: "missing-glue",
          zone: zoneName,
          ns,
          missingFamilies: missingFamilies(glueRec),
          detail: `NS ${ns} 位于被委派区内部，但父区没有提供 glue 地址`,
        });
        if (!hasAddress(external)) {
          nsProblems.set(`${zoneName}|${ns}`, {
            stage: "glue",
            reason: "missing-glue",
            detail: `NS ${ns} 缺少 glue 且无其他解析途径，不可解析`,
          });
        }
      } else if (!inBailiwick && !hasAddress(glueRec) && !hasAddress(external)) {
        addIssue({
          type: "ns-unresolvable",
          zone: zoneName,
          ns,
          detail: `NS ${ns} 既没有 glue，快照中也没有可用的 A/AAAA 解析结果`,
        });
        nsProblems.set(`${zoneName}|${ns}`, {
          stage: "resolution",
          reason: "ns-unresolvable",
          detail: `NS ${ns} 的地址无法解析`,
        });
      }
    }
  }

  // 3. CNAME 位置合法性
  for (const cname of cnames) {
    const name = normalizeName(cname.name);
    const zone = cname.zone ? normalizeName(cname.zone) : zoneOfName(name, new Set(zones.keys()));
    const others = (cname.otherRecords ?? []).filter((t) => t !== "RRSIG" && t !== "NSEC" && t !== "KEY");
    if (zone && name === zone) {
      addIssue({
        type: "cname-conflict",
        name,
        zone,
        detail: "CNAME 出现在区顶点（与 SOA/NS 共存），违反 CNAME 独占性",
      });
    } else if (zone && zones.has(name) && name !== zone) {
      addIssue({
        type: "cname-conflict",
        name,
        zone: name,
        detail: "CNAME 出现在委派点上（该名称同时存在 NS 委派），违反 CNAME 独占性",
      });
    } else if (others.length > 0) {
      addIssue({
        type: "cname-conflict",
        name,
        zone,
        detail: `CNAME 与其他记录（${others.join(", ")}）共存于 ${name}`,
      });
    }
  }

  // 4. 为每个 NS 生成独立解析路径（保留分支，不合并响应）
  const targetZone = chain.length > 0 ? chain[chain.length - 1] : null;
  const paths = [];

  function lookupResponse(ns, zoneName) {
    const byZone = responses[ns] ?? responses[normalizeName(ns)];
    if (!byZone) return null;
    return byZone[zoneName] ?? byZone[normalizeName(zoneName)] ?? null;
  }

  if (targetZone) {
    const targetReferral = zones.get(targetZone).referral ?? {};
    const nsList = (targetReferral.ns ?? []).map(normalizeName);

    for (const ns of nsList) {
      const steps = [];
      const failures = [];

      // 链上每一步的 referral
      for (const zoneName of chain) {
        const zone = zones.get(zoneName);
        const ref = zone.referral ?? {};
        steps.push({
          stage: "referral",
          zone: zoneName,
          ns: (ref.ns ?? []).map(normalizeName),
          glue: ref.glue ?? {},
        });
        const problem = nsProblems.get(`${zoneName}|${ns}`);
        if (problem) failures.push({ zone: zoneName, ...problem });
      }

      // 目标 NS 的权威应答
      const response = lookupResponse(ns, targetZone);
      let authoritative = false;
      if (!response) {
        failures.push({
          stage: "response",
          reason: "no-response",
          detail: `快照中没有 ${ns} 对 ${targetZone} 的应答`,
        });
      } else {
        const rcode = String(response.rcode ?? "NOERROR").toUpperCase();
        const aa = response.aa === true;
        steps.push({
          stage: "answer",
          zone: targetZone,
          ns,
          aa,
          rcode,
        });
        if (DELEGATION_BREAK_RCODES.has(rcode) || !aa) {
          failures.push({
            stage: "response",
            reason: "lame-delegation",
            detail: `${ns} 对 ${targetZone} 返回非权威应答（aa=${aa}, rcode=${rcode}）`,
          });
          addIssue({
            type: "lame-delegation",
            zone: targetZone,
            ns,
            detail: `${ns} 对 ${targetZone} 返回非权威应答（aa=${aa}, rcode=${rcode}）`,
          });
        } else {
          authoritative = true;
        }

        // 只支持部分记录类型
        if (Array.isArray(response.supportedTypes) && !response.supportedTypes.map((t) => t.toUpperCase()).includes(query.type)) {
          failures.push({
            stage: "type-support",
            reason: "partial-type-support",
            detail: `${ns} 不权威支持 ${query.type} 类型（仅支持 ${response.supportedTypes.join(", ")}）`,
          });
          addIssue({
            type: "partial-type-support",
            zone: targetZone,
            ns,
            queryType: query.type,
            supportedTypes: response.supportedTypes,
            detail: `${ns} 只支持部分记录类型，无法权威应答 ${query.type}`,
          });
        }

        if (query.dnssec && response.dnssecOk === false) {
          failures.push({
            stage: "response",
            reason: "dnssec-not-supported",
            detail: `${ns} 的应答未提供 DNSSEC 验证材料`,
          });
        }
      }

      paths.push({
        ns,
        zone: targetZone,
        steps,
        authoritative,
        status: failures.length === 0 ? "ok" : "failed",
        failure: failures.length > 0 ? failures[0] : null,
        failures,
        backupNS: [], // 稍后填充
      });
    }

    // 备用 NS：同区其他状态为 ok 的分支
    const healthy = paths.filter((p) => p.status === "ok").map((p) => p.ns);
    for (const path of paths) {
      path.backupNS = healthy.filter((ns) => ns !== path.ns);
    }
  }

  return {
    query,
    chain,
    targetZone,
    paths,
    issues,
    summary: {
      totalPaths: paths.length,
      okPaths: paths.filter((p) => p.status === "ok").length,
      failedPaths: paths.filter((p) => p.status === "failed").length,
      issueCount: issues.length,
    },
  };
}
