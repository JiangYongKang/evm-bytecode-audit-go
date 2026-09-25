// Package opcodes defines the EVM opcode numbering and metadata used by the
// local bytecode auditor. Only the opcode subset that the decoder
// understands is listed; every other value is INVALID.
package opcodes

// OpCode is a single EVM opcode byte.
type OpCode byte

// Info describes the static metadata of an opcode.
type Info struct {
	Code      OpCode
	Name      string
	Immediate int // number of immediate-data bytes following the opcode (PUSH only)
}

// Instruction is one decoded instruction: its offset within the bytecode,
// the opcode and, for PUSH instructions, its immediate data.
type Instruction struct {
	Offset    int
	Op        OpCode
	Immediate []byte // nil unless Op is PUSH1..PUSH32
}

// EVM opcodes relevant to the auditor.
const (
	STOP         OpCode = 0x00
	ADD          OpCode = 0x01
	MUL          OpCode = 0x02
	SUB          OpCode = 0x03
	DIV          OpCode = 0x04
	LT           OpCode = 0x10
	GT           OpCode = 0x11
	EQ           OpCode = 0x14
	ISZERO       OpCode = 0x15
	CALLER       OpCode = 0x33
	CALLVALUE    OpCode = 0x34
	CALLDATALOAD OpCode = 0x35
	POP          OpCode = 0x50
	MLOAD        OpCode = 0x51
	MSTORE       OpCode = 0x52
	SLOAD        OpCode = 0x54
	SSTORE       OpCode = 0x55
	JUMP         OpCode = 0x56
	JUMPI        OpCode = 0x57
	PC           OpCode = 0x58
	JUMPDEST     OpCode = 0x5b
	PUSH1        OpCode = 0x60
	PUSH2        OpCode = 0x61
	PUSH32       OpCode = 0x7f
	DUP1         OpCode = 0x80
	SWAP1        OpCode = 0x90
	CALL         OpCode = 0xf1
	CALLCODE     OpCode = 0xf2
	DELEGATECALL OpCode = 0xf4
	RETURN       OpCode = 0xf3
	STATICCALL   OpCode = 0xfa
	REVERT       OpCode = 0xfd
	INVALID      OpCode = 0xfe
	SELFDESTRUCT OpCode = 0xff
)

// table is populated in opcodes_table.go.
var table [256]Info
