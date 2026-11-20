import { test } from "node:test";
import assert from "node:assert/strict";
import { analyzeDelegation } from "../src/analyzer.js";

test("正常委派：所有路径权威且状态 ok", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: false },
    zones: {
      com: {
        referral: {
          ns: ["a.gtld-servers.net"],
          glue: { "a.gtld-servers.net": { A: ["192.5.6.30"], AAAA: ["2001:503:a83e::2:30"] } },
        },
        childNS: ["a.gtld-servers.net"],
      },
      "example.com": {
        referral: {
          ns: ["ns1.example.com", "ns2.example.com"],
          glue: {
            "ns1.example.com": { A: ["192.0.2.1"], AAAA: ["2001:db8::1"] },
            "ns2.example.com": { A: ["192.0.2.2"], AAAA: ["2001:db8::2"] },
          },
        },
        childNS: ["ns1.example.com", "ns2.example.com"],
      },
    },
    responses: {
      "ns1.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A", "AAAA"] },
      },
      "ns2.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A", "AAAA"] },
      },
    },
  });

  assert.equal(result.summary.okPaths, 2);
  assert.equal(result.summary.failedPaths, 0);
  assert.equal(result.issues.length, 0);
  for (const path of result.paths) {
    assert.equal(path.status, "ok");
    assert.equal(path.authoritative, true);
    assert.equal(path.failure, null);
  }
});

test("缺少 glue：区内 NS 无 glue 不可解析，区外 NS 作为备用", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: false },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com", "ns2.example.net"],
          glue: {}, // ns1.example.com 缺少 glue
        },
        childNS: ["ns1.example.com", "ns2.example.net"],
      },
    },
    addresses: {
      "ns2.example.net": { A: ["198.51.100.2"] },
    },
    responses: {
      "ns2.example.net": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] },
      },
    },
  });

  const glueIssue = result.issues.find((i) => i.type === "missing-glue");
  assert.ok(glueIssue, "应报告 missing-glue");
  assert.equal(glueIssue.ns, "ns1.example.com");

  const broken = result.paths.find((p) => p.ns === "ns1.example.com");
  assert.equal(broken.status, "failed");
  assert.equal(broken.failure.stage, "glue");
  assert.equal(broken.failure.reason, "missing-glue");
  assert.deepEqual(broken.backupNS, ["ns2.example.net"]);

  const healthy = result.paths.find((p) => p.ns === "ns2.example.net");
  assert.equal(healthy.status, "ok");
});

test("NS 循环委派：两区互相委派且无 glue", () => {
  const result = analyzeDelegation({
    query: { name: "www.a.example", type: "A", dnssec: false },
    zones: {
      "a.example": {
        referral: { ns: ["ns1.b.example"], glue: {} },
      },
      "b.example": {
        referral: { ns: ["ns1.a.example"], glue: {} },
      },
    },
    responses: {},
  });

  const cycle = result.issues.find((i) => i.type === "cyclic-delegation");
  assert.ok(cycle, "应报告 cyclic-delegation");
  assert.ok(cycle.cycle.includes("a.example"));
  assert.ok(cycle.cycle.includes("b.example"));
});

test("部分权威：NS 只支持部分记录类型时分支保留", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "AAAA", dnssec: false },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com", "ns2.example.com"],
          glue: {
            "ns1.example.com": { A: ["192.0.2.1"] },
            "ns2.example.com": { A: ["192.0.2.2"] },
          },
        },
        childNS: ["ns1.example.com", "ns2.example.com"],
      },
    },
    responses: {
      "ns1.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] }, // 不支持 AAAA
      },
      "ns2.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A", "AAAA"] },
      },
    },
  });

  assert.equal(result.paths.length, 2, "不同 NS 的分支必须分别保留");
  const partial = result.paths.find((p) => p.ns === "ns1.example.com");
  assert.equal(partial.status, "failed");
  assert.equal(partial.failure.reason, "partial-type-support");
  assert.deepEqual(partial.backupNS, ["ns2.example.com"]);

  const issue = result.issues.find((i) => i.type === "partial-type-support");
  assert.ok(issue);
  assert.equal(issue.queryType, "AAAA");
});

test("瘸腿委派：非权威应答被识别，权威 NS 作为备用", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: false },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com", "ns2.example.com"],
          glue: {
            "ns1.example.com": { A: ["192.0.2.1"] },
            "ns2.example.com": { A: ["192.0.2.2"] },
          },
        },
        childNS: ["ns1.example.com", "ns2.example.com"],
      },
    },
    responses: {
      "ns1.example.com": {
        "example.com": { aa: false, rcode: "NOERROR" }, // 非权威：瘸腿
      },
      "ns2.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] },
      },
    },
  });

  const lame = result.paths.find((p) => p.ns === "ns1.example.com");
  assert.equal(lame.status, "failed");
  assert.equal(lame.failure.reason, "lame-delegation");
  assert.equal(lame.authoritative, false);
  assert.deepEqual(lame.backupNS, ["ns2.example.com"]);
  assert.ok(result.issues.some((i) => i.type === "lame-delegation"));
});

test("CNAME 冲突：区顶点 CNAME 与委派点 CNAME 均被拒绝", () => {
  const apex = analyzeDelegation({
    query: { name: "example.com", type: "A", dnssec: false },
    zones: {
      "example.com": {
        referral: { ns: ["ns1.example.com"], glue: { "ns1.example.com": { A: ["192.0.2.1"] } } },
        childNS: ["ns1.example.com"],
      },
    },
    responses: {
      "ns1.example.com": { "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] } },
    },
    cnames: [{ name: "example.com", zone: "example.com", target: "elsewhere.net" }],
  });
  const apexIssue = apex.issues.find((i) => i.type === "cname-conflict");
  assert.ok(apexIssue, "区顶点 CNAME 应被标记");
  assert.equal(apexIssue.name, "example.com");

  const coexist = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: false },
    zones: {
      "example.com": {
        referral: { ns: ["ns1.example.com"], glue: { "ns1.example.com": { A: ["192.0.2.1"] } } },
        childNS: ["ns1.example.com"],
      },
    },
    responses: {
      "ns1.example.com": { "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] } },
    },
    cnames: [{ name: "www.example.com", target: "cdn.example.net", otherRecords: ["TXT"] }],
  });
  assert.ok(coexist.issues.some((i) => i.type === "cname-conflict"), "CNAME 与 TXT 共存应被标记");
});

test("委派与子区 NS 不一致被识别", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: false },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com", "ns-old.example.com"],
          glue: {
            "ns1.example.com": { A: ["192.0.2.1"] },
            "ns-old.example.com": { A: ["192.0.2.99"] },
          },
        },
        childNS: ["ns1.example.com", "ns2.example.com"],
      },
    },
    responses: {
      "ns1.example.com": { "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] } },
      "ns-old.example.com": { "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] } },
    },
  });

  const mismatch = result.issues.find((i) => i.type === "delegation-ns-mismatch");
  assert.ok(mismatch, "应报告 delegation-ns-mismatch");
  assert.deepEqual(mismatch.onlyInParent, ["ns-old.example.com"]);
  assert.deepEqual(mismatch.onlyInChild, ["ns2.example.com"]);
});

test("IPv6：AAAA glue 与 AAAA 查询正常工作", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "AAAA", dnssec: false },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com"],
          glue: { "ns1.example.com": { AAAA: ["2001:db8::53"] } }, // 仅 IPv6 glue
        },
        childNS: ["ns1.example.com"],
      },
    },
    responses: {
      "ns1.example.com": {
        "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A", "AAAA"] },
      },
    },
  });

  assert.equal(result.issues.length, 0);
  assert.equal(result.paths.length, 1);
  assert.equal(result.paths[0].status, "ok");
  assert.equal(result.paths[0].authoritative, true);
});

test("DNSSEC：父区缺少 DS 时报告验证链断裂", () => {
  const result = analyzeDelegation({
    query: { name: "www.example.com", type: "A", dnssec: true },
    zones: {
      "example.com": {
        referral: {
          ns: ["ns1.example.com"],
          glue: { "ns1.example.com": { A: ["192.0.2.1"] } },
          ds: false,
        },
        childNS: ["ns1.example.com"],
      },
    },
    responses: {
      "ns1.example.com": { "example.com": { aa: true, rcode: "NOERROR", supportedTypes: ["A"] } },
    },
  });

  assert.ok(result.issues.some((i) => i.type === "dnssec-gap"));
});
