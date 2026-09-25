package opcodes

import "fmt"

// init fills the opcode metadata table. Every opcode not listed here stays
// zero-valued (Name == ""), which Lookup treats as INVALID.
func init() {
	register := func(c OpCode, name string, imm int) {
		table[c] = Info{Code: c, Name: name, Immediate: imm}
	}
	// 0x0 range
	register(STOP, "STOP", 0)
	register(ADD, "ADD", 0)
	register(MUL, "MUL", 0)
	register(SUB, "SUB", 0)
	register(DIV, "DIV", 0)
	// 0x10 range
	register(LT, "LT", 0)
	register(GT, "GT", 0)
	register(EQ, "EQ", 0)
	register(ISZERO, "ISZERO", 0)
	// 0x30 range: environment
	register(CALLER, "CALLER", 0)
	register(CALLVALUE, "CALLVALUE", 0)
	register(CALLDATALOAD, "CALLDATALOAD", 0)
	// 0x50 range: stack / memory / storage / control
	register(POP, "POP", 0)
	register(MLOAD, "MLOAD", 0)
	register(MSTORE, "MSTORE", 0)
	register(SLOAD, "SLOAD", 0)
	register(SSTORE, "SSTORE", 0)
	register(JUMP, "JUMP", 0)
	register(JUMPI, "JUMPI", 0)
	register(PC, "PC", 0)
	register(JUMPDEST, "JUMPDEST", 0)
	// PUSH1..PUSH32
	for i := 1; i <= 32; i++ {
		register(OpCode(int(PUSH1)+i-1), fmt.Sprintf("PUSH%d", i), i)
	}
	register(DUP1, "DUP1", 0)
	register(SWAP1, "SWAP1", 0)
	// 0xf0 range: calls / halts
	register(CALL, "CALL", 0)
	register(CALLCODE, "CALLCODE", 0)
	register(DELEGATECALL, "DELEGATECALL", 0)
	register(RETURN, "RETURN", 0)
	register(STATICCALL, "STATICCALL", 0)
	register(REVERT, "REVERT", 0)
	register(INVALID, "INVALID", 0)
	register(SELFDESTRUCT, "SELFDESTRUCT", 0)
}

// Lookup returns the metadata for op. Unknown opcodes are reported as
// INVALID so callers can distinguish "explicit INVALID" / unknown uniformly
// via IsKnown.
func Lookup(op OpCode) Info {
	info := table[op]
	if info.Name == "" {
		return Info{Code: op, Name: "INVALID", Immediate: 0}
	}
	return info
}

// IsKnown reports whether op has a defined mnemonic.
func IsKnown(op OpCode) bool {
	return op != INVALID && table[op].Name != ""
}

// IsPush reports whether op is one of PUSH1..PUSH32.
func IsPush(op OpCode) bool { return op >= PUSH1 && op <= PUSH32 }

// IsExternalCall reports whether op transfers control to another account.
// STATICCALL cannot mutate state and is excluded (read-only by protocol).
func IsExternalCall(op OpCode) bool {
	return op == CALL || op == CALLCODE || op == DELEGATECALL
}

// IsStateWrite reports whether op mutates contract storage.
func IsStateWrite(op OpCode) bool { return op == SSTORE }

// IsPrivileged reports whether op performs an account-lifetime / fund
// operation that should be access controlled.
func IsPrivileged(op OpCode) bool { return op == SELFDESTRUCT }

func (i Instruction) String() string {
	if len(i.Immediate) > 0 {
		return fmt.Sprintf("%04x: %s 0x%x", i.Offset, Lookup(i.Op).Name, i.Immediate)
	}
	return fmt.Sprintf("%04x: %s", i.Offset, Lookup(i.Op).Name)
}
