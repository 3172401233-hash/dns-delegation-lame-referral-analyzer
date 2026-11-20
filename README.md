# dns-delegation-lame-referral-analyzer

离线权威 DNS 委派分析器。域名的父区委派看似正常时，只检查 NS 列表无法判断解析链在哪一步失效——某个 NS 可能返回非权威应答、另一个缺少 glue 记录、查询还会被游走。本工具从一份**离线 DNS 响应快照**出发，逐步还原从根区到目标区的解析路径，定位失效环节。

> **重要限制**：本分析器只处理离线 DNS 响应快照，不发起任何真实网络查询。所有 referral、glue、权威应答、CNAME 等数据都必须预先采集并写入快照文件。

## 环境要求

- Node.js >= 24.16.0

## 输入快照格式

```json
{
  "query": { "name": "www.example.com", "type": "A", "dnssec": false },
  "zones": {
    "com": {
      "referral": {
        "ns": ["a.gtld-servers.net"],
        "glue": { "a.gtld-servers.net": { "A": ["192.5.6.30"], "AAAA": ["2001:503:a83e::2:30"] } }
      },
      "childNS": ["a.gtld-servers.net"]
    },
    "example.com": {
      "referral": {
        "ns": ["ns1.example.com", "ns2.example.net"],
        "glue": { "ns1.example.com": { "A": ["192.0.2.1"], "AAAA": ["2001:db8::1"] } },
        "ds": true
      },
      "childNS": ["ns1.example.com", "ns2.example.net"]
    }
  },
  "responses": {
    "ns1.example.com": {
      "example.com": { "aa": true, "rcode": "NOERROR", "supportedTypes": ["A", "AAAA"], "dnssecOk": true }
    }
  },
  "addresses": { "ns2.example.net": { "A": ["198.51.100.2"] } },
  "cnames": [{ "name": "www.example.com", "target": "cdn.example.net", "otherRecords": [] }]
}
```

- `query`：查询名称、记录类型与 DNSSEC 标记。
- `zones`：从根到目标区路径上每个区的委派信息。`referral` 是父区给出的 NS 列表与 glue A/AAAA；`childNS` 是子区自己权威应答中的 NS 集合；`ds` 表示父区是否带有 DS 记录。
- `responses`：按 `NS 名称 -> 区 -> 应答` 组织的权威应答快照，含 `aa` 标志、`rcode` 与该 NS 权威支持的记录类型。
- `addresses`：区外 NS 的 A/AAAA 解析结果（用于判断 NS 是否可解析）。
- `cnames`：快照中出现的 CNAME 记录及其同名人处的其他记录类型。

## 检测能力

- **缺少 glue**（`missing-glue`）：NS 位于被委派区内部但父区未提供 glue 地址。
- **NS 不可解析**（`ns-unresolvable`）：NS 既无 glue 也无可用 A/AAAA。
- **委派与子区 NS 不一致**（`delegation-ns-mismatch`）：父区委派列表与子区权威 NS 记录有差异。
- **瘸腿委派**（`lame-delegation`）：NS 返回非权威应答（`aa=0` 或 `REFUSED`/`SERVFAIL`/`NOTAUTH` 等）。
- **循环委派**（`cyclic-delegation`）：多个区互相委派且环节上没有 glue，无法引导解析。
- **CNAME 位置非法**（`cname-conflict`）：CNAME 出现在区顶点、委派点，或与其他记录共存。
- **部分记录类型支持**（`partial-type-support`）：NS 只对部分记录类型权威，无法应答查询类型。
- **DNSSEC 断链**（`dnssec-gap`）：查询要求验证但父区缺少 DS。

不同 NS 返回不同结果时，每个 NS 生成一条独立解析路径（分支），不会只取第一个响应。

## 输出

```json
{
  "query": { "name": "www.example.com", "type": "A", "dnssec": false },
  "chain": ["com", "example.com"],
  "targetZone": "example.com",
  "paths": [
    {
      "ns": "ns1.example.com",
      "zone": "example.com",
      "steps": [{ "stage": "referral", "zone": "com" }, { "stage": "answer", "aa": true }],
      "authoritative": true,
      "status": "ok",
      "failure": null,
      "backupNS": ["ns2.example.net"]
    }
  ],
  "issues": [],
  "summary": { "totalPaths": 1, "okPaths": 1, "failedPaths": 0, "issueCount": 0 }
}
```

每条路径包含：途经的 referral/answer 步骤、权威状态、失败环节（`failure.stage` 为 `glue`/`resolution`/`response`/`type-support` 之一）以及可切换的备用 NS 列表。

## 使用

```bash
node src/cli.js snapshot.json
```

## 测试

```bash
node --test
```

测试覆盖：正常委派、缺少 glue、NS 循环委派、部分权威（记录类型支持不全）、瘸腿委派、CNAME 冲突、委派 NS 不一致、IPv6（AAAA glue）与 DNSSEC 断链。
