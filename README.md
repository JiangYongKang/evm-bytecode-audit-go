# 本地 EVM 字节码安全审计

一个**完全本地、无外部依赖、无凭据**的 EVM 字节码静态审计流程。输入是手工构造的
样例合约字节码（见 `samples` 包），输出是确定性的 JSON 审计结论。畸形输入被拒绝、
风险路径被**路径级**规则（控制流图可达性）命中并附带按执行顺序排列的见证路径证据，
多合约并发审计与串行结论一致且输出顺序稳定。

## 快速开始

```bash
go build ./...
go test ./... -v          # 全部单测（日志含输入摘要与判定依据）
go test -race ./...       # 并发安全检查
go run ./cmd/audit        # 并发审计内置样例，打印 JSON 报告
go run ./cmd/audit -serial  # 串行审计，输出与并发逐字节相同
go run ./cmd/audit -timeout 5s -workers 4
```

仅使用 Go 标准库；不联网，不依赖任何外部服务或真实凭据。

## 支持的字节码范围

解码器（`bytecode` 包）按 Frontier 风格指令集做线性扫描，支持：

- 算术/比较：`STOP ADD MUL SUB DIV LT GT EQ ISZERO`
- 环境：`CALLER CALLVALUE CALLDATALOAD`
- 栈/内存/存储：`POP MLOAD MSTORE SLOAD SSTORE DUP1 SWAP1 PC`
- 控制流：`JUMP JUMPI JUMPDEST`、`PUSH1..PUSH32`
- 外部调用：`CALL CALLCODE DELEGATECALL STATICCALL`
- 终止：`RETURN REVERT INVALID SELFDESTRUCT`

其余操作码一律视为未定义并拒绝。这是一个**刻意收敛的可审计子集**，范围外的字节码
不会被静默放行。

### 拒绝原因（可区分、互斥，首个命中即返回）

| RejectKind | 触发条件 |
|---|---|
| `empty_bytecode` | 输入长度为 0 |
| `invalid_opcode` | 线性扫描遇到未定义操作码或显式 `INVALID(0xfe)`，报告偏移 |
| `truncated_immediate` | `PUSHn` 的立即数超出输入末尾，报告 `PUSH` 偏移与缺失字节数 |
| `jump_target_out_of_bounds` | 紧邻 `JUMP/JUMPI` 之前的 `PUSHk` 目标 ≥ 字节码长度 |
| `jump_target_not_jumpdest` | 上述静态目标存在，但落点不是 `JUMPDEST`（包括落在立即数字节上） |
| `no_halting_path` | 从入口块出发，沿静态控制流图**没有任何可达路径**到达正常结束（见下） |

跳转目标若由运行时动态计算（前一条不是 `PUSH`），静态不可判定，**不**因此拒绝。
被拒绝的输入**不会进入任何规则分析**，报告状态为 `rejected`。

### 正常结束判定（`no_halting_path`）

解码通过后，在控制流图（CFG，见下）上从入口块做 BFS：若所有静态可达块都
无法到达 `STOP`/`RETURN`/`SELFDESTRUCT`，也无法"跑过字节码末尾"（EVM 语义等同
`STOP`），则拒绝。`REVERT` **不**算正常结束。可达的动态跳转（目标静态不可知）
按"可能终止"处理，不误拒。该检查为图上一次遍历，带环输入靠 visited 集合收敛，
不会无限展开。六类拒绝原因互斥、按上述顺序首个命中即返回。

## 规则语义

每条规则有稳定的 `RuleID` 与语义化 `Version`；报告记录命中规则的版本，
规则演进后可用“输入 SHA-256 + 规则 ID/版本”复现历史结论。

| RuleID | 版本 | 语义（保守、局部、可复核） |
|---|---|---|
| `REENTRANCY-STATE-WRITE-AFTER-CALL` | 1.0.0 | 同一基本块内，外部调用（`CALL/CALLCODE/DELEGATECALL`）之后、无终止指令间隔的情况下出现 `SSTORE`。`STATICCALL` 只读，不计。 |
| `UNCHECKED-CALL-RETURN` | 1.0.0 | 外部调用的成功位被**紧邻**的 `POP` 直接丢弃（调用者无从根据失败分支跳转）。后继是 `ISZERO/EQ/JUMPI/DUP*` 等视为“可能已校验”，不报告。 |
| `PRIVILEGED-UNPROTECTED-SELFDESTRUCT` | 1.0.0 | `SELFDESTRUCT` 之前的代码窗口（从上一个 `JUMPDEST` 之后起算）内不同时存在 `CALLER` 与 `EQ`，即缺少调用者身份相等约束。 |

规则是确定性的：相同输入 + 相同规则版本 ⇒ 完全相同的 `Finding` 列表与顺序。
有意保持局部而非全局路径敏感，以换取结论可解释、可复现；样本中
`benign_guarded_selfdestruct` 展示了被识别的 `PUSH owner; CALLER; EQ; ISZERO;
PUSH deny; JUMPI ... SELFDESTRUCT` 所有权模式。

## 证据格式（含路径定位）

每个 `Finding` 至少包含一条 `Evidence`。路径级规则的 `offsets` 是**见证路径**：
按执行顺序列出这条路径上经过的关键位置（调用点/入口点、沿途每个被进入基本块的
`JUMPDEST` 偏移、最终的写入/特权指令偏移），可一段段对着原始字节码核对：

```json
{
  "rule_id": "REENTRANCY-STATE-WRITE-AFTER-CALL",
  "severity": "high",
  "message": "state write at offset 7 is reachable from external CALL at offset 2 along a 2-hop control-flow path (reentrancy window)",
  "evidence": [{
    "description": "an execution path from the external call reaches a storage write; offsets list the path's key positions in execution order",
    "offsets": [2, 6, 7],
    "details": {
      "call_offset": 2, "call_opcode": "CALL",
      "sstore_offset": 7, "state_opcode": "SSTORE",
      "path_blocks": [0, 1],
      "rule_version": "2.0.0"
    }
  }]
}
```

- `offsets` 全部是**原始字节码内的字节偏移**（单测会重新用这些偏移索引原始字节
  并断言操作码）。重入规则：`[call_offset, 沿途块入口..., sstore_offset]`；
  特权规则：`[入口块起点, 沿途块入口..., selfdestruct_offset]`（即绕开守卫的那条
  路径）。环路回边会使偏移序列非单调，这是执行顺序而非偏移排序。
- `details.path_blocks` 给出与 `offsets` 对应的块下标序列；`missing_guard` 说明
  绕过路径上缺失的守卫成分（`CALLER and EQ` / `EQ` / 守卫存在但被绕过）。

## 报告结构

```jsonc
{
  "name": "risky_reentrancy",
  "input_hash": "<sha256 hex，仅由原始字节决定>",
  "byte_len": 7,
  "status": "ok | rejected | error | timeout",
  "reject_kind": "…",      // 仅 rejected
  "reject_detail": "…",
  "findings": [ … ],
  "rule_versions": [ {"rule_id": "…", "version": "1.0.0"}, … ]
}
```

## 并发、故障隔离与缓存

- `audit.Batch` 将结果按**提交下标**写回：无论完成顺序如何，输出顺序恒定；
  多种 worker 数下的并发结论与串行 JSON 逐字节相同（有单测断言）。
- 每个合约独立超时（`-timeout`），超时记 `timeout` 且**不写缓存**；分析内部
  `recover` panic 记 `error`。单合约超时/失败不影响其它合约。
- `audit.Cache` 以输入字节的 SHA-256 为键：每次读取都重新哈希并比对
  `Report.InputHash`，不一致即视为未命中并清除；写入也校验哈希。缓存
  因此不可能为输入 A 返回输入 B 的结论。

## 包结构

| 包 | 职责 |
|---|---|
| `opcodes` | 操作码编号、元数据表与分类谓词 |
| `bytecode` | 解码、类型化拒绝原因、基本块划分、控制流图（`cfg.go`）与停机路径校验 |
| `rules` | 三条确定性风险规则、路径级 BFS 与证据构造（`paths.go` 为共享索引） |
| `audit` | 分析器、报告、哈希缓存、并发批处理 |
| `samples` | 良性/风险/畸形本地样例合约及预期结论 |
| `cmd/audit` | 命令行入口，输出 JSON 报告 |

## 本地复现历史结论

1. 用 `input_hash` 定位当时的原始输入；
2. 用报告中的 `rule_versions` 检出对应规则版本的代码；
3. 对同一字节码重新运行，得到相同 `findings`。
