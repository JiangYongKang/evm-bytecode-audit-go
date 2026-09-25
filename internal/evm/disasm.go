// Package evm 提供 EVM 字节码解码与基本块划分。
package evm

import "fmt"

// RejectReason 区分输入被拒绝的原因类别。
type RejectReason string

const (
	ReasonEmpty         RejectReason = "EMPTY_CODE"
	ReasonUnknownOpcode RejectReason = "UNKNOWN_OPCODE"
	ReasonTruncatedPush RejectReason = "TRUNCATED_PUSH"
	ReasonTooShort      RejectReason = "CODE_TOO_SHORT"
	ReasonBadJumpDest   RejectReason = "JUMP_TARGET_OUT_OF_RANGE"
	ReasonJumpIntoPush  RejectReason = "JUMP_TARGET_NOT_JUMPDEST"
)

// RejectError 表示字节码被拒绝，附带可区分的原因。
type RejectError struct {
	Reason RejectReason
	Offset int
	Detail string
}

func (e *RejectError) Error() string {
	return fmt.Sprintf("rejected(%s) at offset %d: %s", e.Reason, e.Offset, e.Detail)
}

// Instruction 是一条解码后的指令。
type Instruction struct {
	PC  int
	Op  OpCode
	Imm []byte // PUSH 立即数
}

// Name 返回指令的操作码名称。
func (in Instruction) Name() string { return opcodeTable()[in.Op].Name }

// PushValue 在指令为 PUSH 且立即数可放入 uint64 时返回其值。
func (in Instruction) PushValue() (uint64, bool) {
	if len(in.Imm) == 0 || len(in.Imm) > 8 {
		return 0, false
	}
	var v uint64
	for _, b := range in.Imm {
		v = v<<8 | uint64(b)
	}
	return v, true
}

// OpCode 表示一个 EVM 操作码。
type OpCode byte

// 常用操作码常量。
const (
	OpStop         OpCode = 0x00
	OpJump         OpCode = 0x56
	OpJumpi        OpCode = 0x57
	OpJumpdest     OpCode = 0x5b
	OpSstore       OpCode = 0x55
	OpCall         OpCode = 0xf1
	OpCallcode     OpCode = 0xf2
	OpDelegatecall OpCode = 0xf4
	OpStaticcall   OpCode = 0xfa
	OpReturn       OpCode = 0xf3
	OpRevert       OpCode = 0xfd
	OpInvalid      OpCode = 0xfe
	OpSelfdestruct OpCode = 0xff
	OpIszero       OpCode = 0x15
	OpPop          OpCode = 0x50
	OpCaller       OpCode = 0x33
	OpOrigin       OpCode = 0x32
	OpEq           OpCode = 0x14
	OpSload        OpCode = 0x54
)

// IsTerminator 判断是否为终止当前基本块的指令。
func (op OpCode) IsTerminator() bool {
	switch op {
	case OpStop, OpReturn, OpRevert, OpInvalid, OpSelfdestruct, OpJump, OpJumpi:
		return true
	}
	return false
}

// IsHalting 判断是否为停止执行的指令（不含跳转）。
func (op OpCode) IsHalting() bool {
	switch op {
	case OpStop, OpReturn, OpRevert, OpInvalid, OpSelfdestruct:
		return true
	}
	return false
}

// IsCall 判断是否为外部调用类指令。
func (op OpCode) IsCall() bool {
	switch op {
	case OpCall, OpCallcode, OpDelegatecall, OpStaticcall:
		return true
	}
	return false
}

// IsPrivileged 判断是否为特权（高影响）指令。
func (op OpCode) IsPrivileged() bool {
	switch op {
	case OpSelfdestruct, OpDelegatecall, OpCallcode:
		return true
	}
	return false
}

// BasicBlock 是一段顺序执行、以跳转/终止指令结尾的指令序列。
type BasicBlock struct {
	Start  int
	Instrs []Instruction
}

// Program 是解码并校验后的合约程序。
type Program struct {
	Code      []byte
	Instrs    []Instruction
	Blocks    []BasicBlock
	JumpDests map[int]bool
}

// Decode 解码字节码并做结构校验；失败返回 *RejectError。
func Decode(code []byte) (*Program, error) {
	if len(code) == 0 {
		return nil, &RejectError{Reason: ReasonEmpty, Offset: 0, Detail: "bytecode is empty"}
	}
	tbl := opcodeTable()

	// 第一遍：逐条解码，校验操作码与立即数长度。
	var instrs []Instruction
	pushData := make([]bool, len(code))
	for pc := 0; pc < len(code); {
		b := code[pc]
		info := tbl[b]
		if info == nil {
			return nil, &RejectError{
				Reason: ReasonUnknownOpcode, Offset: pc,
				Detail: fmt.Sprintf("byte 0x%02x is not a supported opcode", b),
			}
		}
		ins := Instruction{PC: pc, Op: OpCode(b)}
		if info.ImmSize > 0 {
			if pc+info.ImmSize >= len(code) {
				return nil, &RejectError{
					Reason: ReasonTruncatedPush, Offset: pc,
					Detail: fmt.Sprintf("%s needs %d immediate bytes, only %d remain",
						info.Name, info.ImmSize, len(code)-pc-1),
				}
			}
			ins.Imm = code[pc+1 : pc+1+info.ImmSize]
			for i := pc + 1; i <= pc+info.ImmSize; i++ {
				pushData[i] = true
			}
			pc += 1 + info.ImmSize
		} else {
			pc++
		}
		instrs = append(instrs, ins)
	}

	// 代码必须在停止/跳转指令处结束，否则视为长度不足。
	last := instrs[len(instrs)-1]
	if !last.Op.IsTerminator() {
		return nil, &RejectError{
			Reason: ReasonTooShort, Offset: last.PC,
			Detail: fmt.Sprintf("code falls off the end after %s without a terminating instruction", last.Name()),
		}
	}

	// 收集合法跳转目标。
	jumpDests := make(map[int]bool)
	for _, in := range instrs {
		if in.Op == OpJumpdest {
			jumpDests[in.PC] = true
		}
	}

	// 第二遍：校验可静态解析的跳转目标。
	for i, in := range instrs {
		if in.Op != OpJump && in.Op != OpJumpi {
			continue
		}
		if i == 0 {
			continue
		}
		prev := instrs[i-1]
		target, ok := prev.PushValue()
		if !ok {
			continue // 动态目标，无法在本地静态判定
		}
		if target >= uint64(len(code)) {
			return nil, &RejectError{
				Reason: ReasonBadJumpDest, Offset: in.PC,
				Detail: fmt.Sprintf("%s at pc=%d targets %d, beyond code length %d",
					in.Name(), in.PC, target, len(code)),
			}
		}
		if pushData[target] || !jumpDests[int(target)] {
			return nil, &RejectError{
				Reason: ReasonJumpIntoPush, Offset: in.PC,
				Detail: fmt.Sprintf("%s at pc=%d targets %d which is not a JUMPDEST",
					in.Name(), in.PC, target),
			}
		}
	}

	// 基本块划分：在 JUMPDEST 处开始新块，终止/跳转指令后结束当前块。
	var blocks []BasicBlock
	var cur []Instruction
	flush := func() {
		if len(cur) > 0 {
			blocks = append(blocks, BasicBlock{Start: cur[0].PC, Instrs: cur})
			cur = nil
		}
	}
	for _, in := range instrs {
		if in.Op == OpJumpdest {
			flush()
		}
		cur = append(cur, in)
		if in.Op.IsTerminator() {
			flush()
		}
	}
	flush()

	return &Program{Code: code, Instrs: instrs, Blocks: blocks, JumpDests: jumpDests}, nil
}
