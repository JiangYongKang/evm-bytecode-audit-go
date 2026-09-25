# evm-bytecode-audit-go

本地 EVM 字节码安全审计工具：对本地样例合约字节码做解码校验、基本块划分、
基于规则的风险路径识别，并支持并发批量审计。全部流程离线运行，仅依赖 Go 标准库。

## 构建与运行

```bash
go build ./...
go test ./... -v          # 运行全部测试（日志含输入摘要与判定依据）
go test ./... -race       # 并发正确性校验

# 命令行：分析内联十六进制或本地 hex 文件
go run ./cmd/audit -hex 0x6000600060006000600060006000f1600160005500 -hex 0x6000ff
go run ./cmd/audit ./samples/*.hex
```

退出码：任一合约被 FLAGGED 或执行出错时为 1，全部 CLEAN 为 0，参数错误为 2。

## 支持的字节码范围

- 操作码覆盖 Frontier ~ Shanghai 的常用指令集（算术、环境、内存/存储、
  PUSH0/PUSH1-32、DUP/SWAP、LOG0-4、CALL 家族、CREATE/CREATE2、
  RETURN/REVERT/INVALID/SELFDESTRUCT 等），见 `internal/evm/opcodes.go`。
- 未列出的字节一律视为**非法操作码**并拒绝。
- 解码后按 JUMPDEST 与终止/跳转指令划分基本块。

### 畸形输入的拒绝原因（可区分）

| RejectReason | 含义 |
|---|---|
| `EMPTY_CODE` | 字节码为空 |
| `UNKNOWN_OPCODE` | 出现不支持的操作码字节 |
| `TRUNCATED_PUSH` | PUSHn 立即数被截断（剩余字节不足 n） |
| `CODE_TOO_SHORT` | 代码在未终止指令处结束（fall off the end） |
| `JUMP_TARGET_OUT_OF_RANGE` | 可静态解析的跳转目标超出代码长度 |
| `JUMP_TARGET_NOT_JUMPDEST` | 跳转目标不是 JUMPDEST（含落入 PUSH 立即数） |

被拒绝的输入不会进入规则分析，报告中以 `Status=REJECTED` + 上述原因返回。
动态跳转目标（非 PUSH 立即数可解析）不在本地静态判定范围内，予以放行。

## 规则语义

规则在**基本块内**做模式匹配，结论确定、可复现：

| RuleID | 语义 |
|---|---|
| `REENTRANCY_STATE_WRITE_AFTER_CALL` | 同一基本块内，可改状态的外部调用（CALL/CALLCODE/DELEGATECALL，不含 STATICCALL）之后仍出现 SSTORE |
| `UNCHECKED_CALL_RETURN` | 调用返回值未在块内被 ISZERO 校验（含被立即 POP 丢弃） |
| `UNGUARDED_PRIVILEGED_OP` | SELFDESTRUCT/DELEGATECALL/CALLCODE 之前，块内没有 CALLER/ORIGIN 鉴权检查 |

每份报告带 `RulesetID`（由规则 ID 集合哈希派生）：同一 `(RulesetID, 输入)`
必得一致报告；规则调整后 RulesetID 变化，历史结论可按原 RulesetID 复现核对。

## 证据格式

每条命中附带 `Evidence`：

```
<RuleID> block#<基本块序号> pcs=[0x..,0x..] <人类可读的判定依据>
```

例如：

```
REENTRANCY_STATE_WRITE_AFTER_CALL block#0 pcs=[0xe,0x13] SSTORE at pc=19 follows state-changing call at pc=14 in the same block
```

`pcs` 为可核对的指令偏移（十六进制），可直接对照原始字节码验证。

## 并发批量审计

`BatchAuditor` 以 worker 池并发分析多个合约：

- 输出顺序与输入顺序一致（按 `Index` 对齐），与串行分析结论逐一相等；
- 每个合约有独立超时（`PerContractTimeout`），单个超时/失败不影响其它合约；
- 缓存键为 `RulesetID + 字节码 SHA-256`，命中时再次校验哈希，不会返回与输入不匹配的结果。

## 本地验证方法

```bash
go test ./internal/evm/ -v    # 畸形字节码分类：日志打印输入摘要与拒绝原因
go test ./internal/audit/ -v  # 风险路径命中证据、确定性、并发一致性、缓存匹配
```

测试样例合约为手工构造的运行时字节码（见 `internal/audit/analyzer_test.go`），
覆盖可重入路径、返回值未校验、特权指令有/无鉴权、截断立即数等场景。
