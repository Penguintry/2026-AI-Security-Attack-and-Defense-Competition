---
title: "WRITEUP"
---

# WRITEUP（数据投毒安全检测类题目）

## 解题情况

本场共解出 **6** 题，全部获取 flag：

| 序号 | 题目名称 | 状态 | flag |
|------|----------|------|------|
| 1 | Neuro token vm | ✅ 已解 | `flag{f585dc57-9657-4591-9bbb-14b05ffd868e}` |
| 2 | Noisy Digits | ✅ 已解 | `flag{4245326d-43a5-4397-b744-5265a2ee4b4f}` |
| 3 | falseanchor | ✅ 已解 | `flag{bf56c6de-0d3f-4030-aefb-74cf5f1e3814}` |
| 4 | labelshift | ✅ 已解 | `flag{02af40c9-c947-45a2-b5b7-24ae2a44cc56}` |
| 5 | vectorworld | ✅ 已解 | `flag{4aec7f43-f90d-45b0-8002-3b689a74438e}` |
| 6 | needle (NeedleRank) | ✅ 已解 | `flag{fdf97b19-00b6-4f01-9fd9-80713c339d3f}` |

（提交时请替换战队名称、排名，并粘贴排行榜与答题情况截图）

## 解题过程

---

### 题目 1｜Neuro token vm

**题目描述：**

The token routing table of a certain tiny-bpe.q4 checkpoint has experienced drift. The program only accepts one prompt token that can align the logits. 请逆向附件，恢复正确输入。Flag 格式：flag{uuid}。

**附件：** `neuro_token_vm.exe`（PE64 MinGW，stripped）

**操作内容：**

**1. 侦察。** 提取程序字符串，发现提示语 "prompt token> "、"accepted: logits aligned"、"rejected: token drift detected"，并确认输入校验包含 "flag{"（42 字符格式）。用 WSL objdump 反汇编主函数 `0x1400029f0`：

- `fgets` 读入，`strlen==42`，前缀 `flag{`、末位 `}`；
- UUID 部分（36 字符）按位掩码 `0x842100` 校验：bit 8/13/18/23 处必须为 `-`（记 0x10），其余必须是小写 hex（记 0-15）。

**2. VM 指令还原。** .rdata 段 `0x40a0` 处有一张 352+ 字节异或混淆表 T（题面字符串 `297cL`、`J/:3 !;k` 等藏于表中）。VM 指令按 `val(i) = (13i − 0x59) & 0xFF ^ T[i]` 分派：

- `0x10`：取 `buf2[val(i+1)]` 入 esi，`r10b = val(i+1)`；
- `0x20`：`edx = (val(i+4)·edx + val(i+2)·esi + val(i+3) + val(i+1)·r10b) mod 0xfff1`；
- `0x30`：校验 `(val(i+2)<<8 | val(i+1)) == edx`；
- `0xFF`：接受。

**3. 同余方程求解。** 程序流为 36 轮（k=0..35）链式同余方程：

```
B_k · buf2[k] ≡ X_k − A_k·edx − C_k − D_k·k (mod 0xfff1)
```

edx 初值 0x4d2d，逐轮用扩展欧几里得求逆解出 36 个值（8/13/18/23 位自然解出 0x10='-'）。每位唯一解。

**4. 验证。** 输入解出的 key，程序输出 "accepted: logits aligned"；改动任意字节即 "rejected: token drift detected"。

**flag值：**

```
flag{f585dc57-9657-4591-9bbb-14b05ffd868e}
```

---

### 题目 2｜Noisy Digits

**题目描述：**

手写数字识别模型的对抗攻击测试。攻击目标在传输中引入了椒盐噪声。分析附件并在指定 ip:port 提交（无前端界面）。

**附件：** `check.py`、`mnist_label_1_noisy.png`、`modelofmnist.pth`

**操作内容：**

**1. 判定条件分析。** `check.py` 要求：提交 9 张图的 base64，服务端校验 `ssim(attack, original) >= 0.65 且 conf > 0.75 且 pred == 9` 才输出 flag。原始图为 `mnist_label_1.png`（服务端持有），附件只有带噪版本。

**2. 噪声恢复。** 分析带噪图：784 像素中 **721 个是椒盐噪声**（0/255 极值，92%）。用 3x3 中值滤波只替换极值像素，恢复出清晰的"1"字形（恢复图被模型以 conf 0.995 判为 1）。

**3. L2 球 PGD 攻击。** 以恢复图为基底做目标类 9 的 PGD（动量 0.9，2000 步），约束 L2 半径并自实现 SSIM（11x11 高斯窗，C1=0.01²、C2=0.03²）评估。半径扫描结果：

| 半径 | 预测 | 置信度 | SSIM |
|---|---|---|---|
| 2.5 | 9 | 0.781 | 0.747 |
| **3.0** | **9** | **0.964** | **0.721** ✅ |
| 3.5 | 9 | 0.993 | 0.678 |

取 r=3.0：三项判定全部达标且有余量。

**4. 提交。** 攻击图转 PNG base64，`nc 39.106.48.123 20444` 发送，服务端返回 flag。

**flag值：**

```
flag{4245326d-43a5-4397-b744-5265a2ee4b4f}
```

---

### 题目 3｜falseanchor（Clean-label RAG Backdoor）

**题目描述：**

Please refer to the README.md file in the attachment.（RAG 服务基于反馈目录与知识库做信任打分和检索，需投毒使攻击文档通过信任门槛并执行动作。）

**附件：** `api_contract.md`、`challenge_description.md`、`feedback_catalog.json`、`kb_snapshot.json`、`poison_contract.json`、`replay.py`

**操作内容：**

**1. 机制审计。** 检索分 = `0.55·dense + 0.25·lexical + 0.20·trust`；trust = `0.35·semantic + 0.65·profile_match`；action_threshold 0.68。信任 profile = 提交批次中 trusted 反馈行共享的非停用词（≥半数行）。检测器不检查 batch 内共享触发短语、不校验 label 来源签名；反馈导入按 record_id 合并，**文本不可变但 label 可被覆盖**（FB-009 untrusted→trusted）。

**2. 投毒反馈批次**（8 行，1 次导入）：

- 覆盖 FB-009 标签为 trusted；
- 新增 4 条自然 trusted 反馈，全部共享激活短语 "service recovery exercise" 与动作词（service/recovery/exercise/export/audit/bundle）；
- 配 3 条 untrusted 行平衡标签；
- 所有行避开原始 profile 词（review 等）与注入语法，行间 Jaccard ≤0.56 规避 near-duplicate 检测。

**3. 注入知识文档**（1 篇）：策略风格文档，title+body 含激活短语原文及 export/audit/bundle/authorized 等词，不含 control 查询词（incident/evidence），action_code = `EXPORT-AUDIT-BUNDLE`。

**4. rebuild 验证**：detector=clean，learned profile=[audit, recovery, service] 恰好全在攻击文档 → profile_match=1.0。

**5. evaluate + execute**：

| 判定 | 结果 |
|---|---|
| trigger_pass | **4/4**（攻击文档 Top-1 且得分 0.686-0.835 > 0.68 门槛） |
| control_pass | **3/3**（control 查询得分 0.538-0.635 < 门槛，non-actionable） |
| trust lift | 0.1957 → 0.8928（**+0.697**，要求 ≥0.08） |

execute 通过后服务端返回 flag。

**flag值：**

```
flag{bf56c6de-0d3f-4030-aefb-74cf5f1e3814}
```

---

### 题目 4｜labelshift（Release Forensics）

**题目描述：**

Please refer to the README.md file in the attachment.（离线取证：标签漂移事故。生成 incident_report.json 并通过本地 Evidence Vault 验证。）

**附件：** `train.jsonl`、`imports.csv`、`clean_anchors.jsonl`、`router_checkpoint.json`、`replay.py`、`canary_suite.jsonl`、`vault.py`、`vault.json`

**操作内容：**

**1. 数据盘点。** train.jsonl 共 960 行（4 标签各 240），7 个批次（ingest-*、legacy-label-07、sync-*）。`vault.py` 验证报告：routing_profile（5-12 词、24-48 支持、单批次、SECURITY 标签纯）、review_source、label_corrections（8-24 条、保平衡、语义增益 ≥3.0）。

**2. 标签漂移定位（review_source）。** 用 clean_anchors（24 条独立审核锚点）对每行计算最佳标签，发现 **legacy-label-07 有 16 行错配**（SECURITY→BILLING×2、ACCESS→GENERAL×2 等），修正后恰好保持标签平衡，语义增益 11.57 ≥ 3.0。

**3. 投毒 profile 定位（routing_profile）。** 全语料扫描所有 5-12 词连续切片（5254 个唯一候选），过滤支持 24-48 + SECURITY 纯 + 单批次，得到 29 个候选；再用 checkpoint 的 SECURITY 权重验证 feature_contrasts（≥5 正特征、总和 ≥3.2）与 canary 反事实（delta ≥4.8、margin ≥0.75、9/9 attacked=SECURITY），仅 2 个通过，均来自 sync-aurora-17（36 支持）：

- `case owner verified the retained incident evidence archive`（8 词）

7 词版本在修复后模型验证中失败（其提升主要来自 w:owner/w:incident，在语料其他行仍存续，repaired delta 1.2512 > 1.2），8 词版本加入 w:archive（负权重）与 b:evidence_archive（profile 行独占）使 repaired delta 1.1150 ≤ 1.2 达标。

**4. 报告提交。** 构造 incident_report.json（profile + profile_record_ids 36 个 + review_source=legacy-label-07 + 16 条 corrections），运行 `vault.py incident_report.json`，Evidence Vault 打开返回 flag。

**flag值：**

```
flag{02af40c9-c947-45a2-b5b7-24ae2a44cc56}
```

---

### 题目 5｜vectorworld（Index Provenance Incident）

**题目描述：**

Please refer to the README.md file in the attachment.（防御审计：企业向量索引迁移事故。重建每个公开记录的声明嵌入、验证来源承诺、关联历史事故并提交证据。）

**附件：** `api_contract.md`、`audit_contract.md`、`README.md`、`starter_audit.py`

**容器：** `http://8.147.132.32:22975`

**操作内容：**

**1. 契约审计。** source digest = UTF-8 SHA-256 of：

```
Title: {title}\nSource: {source}\nDate: {date}\n\nContent:\n{body}
```

向量 digest = SHA-256(model_id \x00 model_revision \x00 pipeline_version \x00 dim(LE u32) + quantized int16 LE bytes)，量化 = `clip(rint(normalized*32767), -32768, 32767).astype('<i2')`。

**2. 关键坑：instance 与 session 绑定。** 每次新会话 GET /api/challenge 生成新 instance_id，bundle 中 96 个文档 ID 与篡改位置**全部随机化**——必须**同一 opener/cookie 会话内**完成全流程（challenge → bundle → 本地对比 → recompute → incidents → submit → replay）。

**3. 一体化解题**（单会话脚本 solve_final.py）：

- GET /api/audit-bundle → 96 文档 + 96 索引行；
- 本地计算 source digest 对比 `declared_source_commitment` → **source_tamper**（本例 `KB-49C67FA76781`，内容被篡改）；
- 分批（32/批）POST /api/audit/recompute → 对比 expected_vector_digest（按声明 pipeline 重算）vs stored_vector_digest（索引存储）→ **vector_substitution**（本例 `KB-C15DD225A989`，存储向量被替换）；
- GET /api/incidents → 14 个历史事件中，Top-5 含被替换向量文档且 action≠NONE 的事件 = **affected_incident**（本例 `INC-F3BC998EC0B3`，不安全动作 PAYROLL_CONTINUITY_OVERRIDE）；
- POST /api/audit/submit 提交 4 个 digest（vector_expected / vector_stored / source_current / source_declared）→ 返回签名的 audit_token；
- POST /api/incidents/replay {audit_token, incident_id} → 服务端对比存储索引（Top-1 = 被替换向量 → OVERRIDE 动作）与干净索引（Top-1 = 正确文档 → NONE 动作），root_cause=STORED_VECTOR_SUBSTITUTION，返回 flag。

**flag值：**

```
flag{4aec7f43-f90d-45b0-8002-3b689a74438e}
```

---

### 题目 6｜needle (NeedleRank)

**题目描述：**

Please refer to the README.md file in the attachment.（单文档混合检索投毒：提交一篇 contractor 恢复笔记，使其在 3 条隐藏改写查询上 BM25 rank ≤3、dense rank ≤3、RRF 融合 rank 1 严格高于官方文档。）

**附件：** `README.md`、`challenge_description.md`、`api_contract.md`、`retrieval_spec.json`、`tools/candidate_lint.py`

**容器：** `http://47.95.110.129:24588`

**操作内容：**

**1. 机制分析。** 检索 = BM25（k1=1.35, b=0.72）+ Qwen3-Embedding-0.6B 余弦 + RRF 融合（k=40）。文档约束：45-90 tokens、唯一率 ≥0.62、token ≤3 次、1 个独立行 Resolution-Code。RRF 数学：trusted 满分 (1,1)=0.04878；候选必须 (1,1) 才能严格大于（(1,2) 与 trusted (2,1) 打平 0.04820 判负）。

**2. 隐藏查询词逆向（词级梯度）。** 提交不消耗预算，可无限测试。两类实验揭示 3 条隐藏查询的词表：

- **fishing 实验**（806 个候选词逐个追加，观测 6 位小数 BM25 分数差分，垃圾词漂移校准）：命中 case1 `frozen`(+1.87)/`recover`(+1.33)、case2 `procedure`(+0.86)、case3 `failure`(+2.14)/`rotation`(+1.08)；虚词也是查询词且高 IDF：case1 `how`/`should`(+2.85)、case2 `which`(+3.24)、case3 `how`/`can`(+3.22)/`after`。
- **removal 实验**（逐 token 移除看各 case 分数下降）：case1 大词 `recover`(2.68)/`key`(0.85)，case2 `disabled`(1.68)/`restores`(1.45)，case3 `regain`(2.93)/`finance`(1.45)/`payment`(0.75)；并证明 case1 查询不含 restore、case3 不含 payroll/signing。

**3. 镜像查询法（最终文档 v40，52 tokens）。** 将 body 直接按三条隐藏查询的真实措辞写成问句：

```
How should Atlas recover payroll when the lunar signing key becomes frozen?
Which procedure restores payroll access for a disabled credential?
How can Atlas regain finance payment access after lunar rotation failure?
Verify the lunar key, recover that key, regain access to finance payment,
re-enable disabled credentials, restore frozen keys.
Resolution-Code: quartz-8
```

**4. 评估与获取。** POST /api/submit → POST /api/evaluate：case1 (bm25=1, dense=1)、case2 (1,1)、case3 (1,1)，**3/3 passed**，全部 fused rank 1 严格高于 trusted。POST /api/recover → 服务端重跑检索，采纳 contractor 文档的 Resolution-Code → 返回 flag。

**flag值：**

```
flag{fdf97b19-00b6-4f01-9fd9-80713c339d3f}
```

---
