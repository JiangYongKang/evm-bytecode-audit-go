# 本地 EVM 字节码安全审计

一个**完全本地、无外部依赖、无凭据**的 EVM 字节码静态审计流程。输入是手工构造的
样例合约字节码（见 `samples` 包），输出是确定性的 JSON 审计结论。畸形输入被拒绝、
风险路径被规则命中并附带可核对证据，多合约并发审计与串行结论一致且输出顺序稳定。

本轮升级：风险判定从“看局部片段”升级为**看整条可执行路径**——规则在控制流图
（CFG）上做可达性分析，跨基本块、跨分支汇合、跨跳转绕行都能命中或排除，并给出
按执行顺序排列的路径定位信息。

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
| `no_reachable_exit` | 解码与静态跳转都合法，但从入口出发**没有任何可达路径**能正常结束（`STOP/RETURN/SELFDESTRUCT` 或走出代码末尾）；例如只剩死循环。这是路径级拒绝，与上面的解码期拒绝互不重叠 |

跳转目标若由运行时动态计算（前一条不是 `PUSH`），静态不可判定，**不**因此拒绝。
被拒绝的输入**不会进入任何规则分析**，报告状态为 `rejected`。

## 控制流图（CFG）

`bytecode.BuildCFG` 在基本块上构建控制流图，是所有路径级判定的基础：

- `JUMP`：目标是紧邻的前一条 `PUSHk` 时静态解析到对应 `JUMPDEST` 块；
- `JUMPI`：静态目标块 + 顺序落空块两条出边；
- 动态计算的目标（前一条不是 `PUSH`）：保守地近似为**所有 `JUMPDEST` 块**
  （may-分析的上近似），保证“存在路径”类判定不漏报；
- `STOP/RETURN/REVERT/SELFDESTRUCT`：无出边；块末尾无终止指令则落到下一块，
  最后一块走出末尾视为隐式 `STOP`（正常结束）。

后继列表按块号升序去重，遍历顺序对同一输入恒定。

## 规则语义（路径级）

每条规则有稳定的 `RuleID` 与语义化 `Version`；报告记录命中规则的版本，
规则演进后可用“输入 SHA-256 + 规则 ID/版本”复现历史结论。

| RuleID | 版本 | 语义 |
|---|---|---|
| `REENTRANCY-STATE-WRITE-AFTER-CALL` | **2.0.0** | **may-路径分析**：从每个外部调用（`CALL/CALLCODE/DELEGATECALL`）之后的程序点出发，只要存在**任意一条**可达路径最终执行 `SSTORE` 即命中一次，并给出一条见证路径。调用后所有路径都先终止、写不到状态时不报。`STATICCALL` 只读，不计。 |
| `UNCHECKED-CALL-RETURN` | 1.0.0 | 外部调用的成功位被**紧邻**的 `POP` 直接丢弃。后继是 `ISZERO/EQ/JUMPI/DUP*` 等视为“可能已校验”，不报告。（本轮未改语义） |
| `PRIVILEGED-UNPROTECTED-SELFDESTRUCT` | **2.0.0** | **must-路径分析**：只有当从入口到 `SELFDESTRUCT` 的**每一条**可达路径都先完成调用者身份校验（同一块或前面块中出现 `CALLER`+`EQ` 对）才算受约束；存在任意一条绕开校验的可达路径即报一次，并给出绕行见证路径。不可达的 `SELFDESTRUCT` 不会执行，不报。 |

环路/回边：重入用带访问标记的 BFS，特权判定用单调不动点（最大不动点，
比特只翻一次），都保证收敛、不重复报、不漏报。规模边界：复杂度为
O(块数 × 边数)，数百块、密集回边的输入在毫秒级出结论（有单测覆盖）。

规则是确定性的：相同输入 + 相同规则版本 ⇒ 完全相同的 `Finding` 列表与顺序，
与 worker 数、串行/并发无关（有逐字节比对单测）。

### 版本兼容范围

- `REENTRANCY-STATE-WRITE-AFTER-CALL` 1.0.0 → 2.0.0：从“同基本块内相邻”
  扩展为“跨块可达”。2.0.0 是 1.0.0 的严格超集：1.0.0 命中的输入 2.0.0 仍命中，
  但 2.0.0 会额外命中跨块路径（例如 `risky_combo` 现在报两条重入）。
- `PRIVILEGED-UNPROTECTED-SELFDESTRUCT` 1.0.0 → 2.0.0：从“局部窗口”改为
  “全路径约束”。1.0.0 判安全的跨块绕行输入，2.0.0 会报；1.0.0 因窗口过窄的
  误报（保护在别的代码段）在 2.0.0 下消失。
- 历史结论复现：按报告中的 `rule_versions` 检出对应版本的实现，对同一
  `input_hash` 重跑即可逐字节复现当时的结论。

## 路径定位信息格式

路径级 Finding 的证据按**执行顺序**给出关键位置，全部是原始字节码的字节偏移，
可一段段对着输入核对：

```json
{
  "rule_id": "REENTRANCY-STATE-WRITE-AFTER-CALL",
  "severity": "high",
  "message": "state write at offset 7 is reachable from external CALL at offset 2 via 2 block(s) (reentrancy window)",
  "evidence": [{
    "description": "a control-flow path from the external call reaches a storage write; offsets are in execution order",
    "offsets": [2, 6, 7],
    "details": {
      "call_offset": 2, "call_opcode": "CALL",
      "sstore_offset": 7, "state_opcode": "SSTORE",
      "path_blocks": [0, 1], "path_offsets": [2, 6, 7],
      "rule_version": "2.0.0"
    }
  }]
}
```

- 重入：`offsets = [调用偏移, 途经各块起始偏移…, SSTORE 偏移]`；
  `path_blocks` 是对应的基本块序号。
- 特权：`offsets = [入口块起始偏移(0), 绕行途经各块起始偏移…, SELFDESTRUCT 偏移]`；
  `missing_guard` 说明见证路径上缺的是 `CALLER`、`EQ` 还是两者。
- 见证路径由“后继按块号升序的 BFS”产生，是最短且确定的一条。

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
  "rule_versions": [ {"rule_id": "…", "version": "2.0.0"}, … ]
}
```

## 并发、故障隔离与缓存

- `audit.Batch` 将结果按**提交下标**写回：无论完成顺序如何，输出顺序恒定；
  多种 worker 数下的并发结论与串行 JSON 逐字节相同（有单测断言）。
- 每个合约独立超时（`-timeout`），超时记 `timeout` 且**不写缓存**；分析内部
  `recover` panic 记 `error`。单合约超时/失败/拒绝不影响其它合约。
- `audit.Cache` 以输入字节的 SHA-256 为键：每次读取都重新哈希并比对
  `Report.InputHash`，不一致即视为未命中并清除；写入也校验哈希。缓存
  因此不可能为输入 A 返回输入 B 的结论。

## 包结构

| 包 | 职责 |
|---|---|
| `opcodes` | 操作码编号、元数据表与分类谓词 |
| `bytecode` | 解码、类型化拒绝原因、基本块划分、控制流图与可达出口检查 |
| `rules` | 三条确定性风险规则（两条路径级）与证据构造 |
| `audit` | 分析器、报告、哈希缓存、并发批处理 |
| `samples` | 良性/风险/畸形本地样例合约及预期结论 |
| `cmd/audit` | 命令行入口，输出 JSON 报告 |

## 本地复现历史结论

1. 用 `input_hash` 定位当时的原始输入；
2. 用报告中的 `rule_versions` 检出对应规则版本的代码；
3. 对同一字节码重新运行，得到相同 `findings`。

## 本地验证本轮结论

```bash
# 路径级命中/排除、环路收敛、回归拒绝
go test ./rules/ ./bytecode/ -v

# 串行 vs 并发逐字节一致（含新路径样例）
go test ./audit/ -run 'ConcurrentEqualsSerial|LargeContract' -v
go run ./cmd/audit -serial > /tmp/a.json && go run ./cmd/audit -workers 8 > /tmp/b.json && cmp /tmp/a.json /tmp/b.json

# 回归：走不到正常结束的输入被明确拒绝（no_reachable_exit）
go test ./audit/ -run NoReachableExitRegression -v
```
