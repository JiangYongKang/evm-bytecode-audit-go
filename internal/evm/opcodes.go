package evm

import "fmt"

// opcodeInfo 描述一个操作码的名称与立即数字节数。
type opcodeInfo struct {
	Name    string
	ImmSize int // PUSHn 的立即数字节数，其余为 0
}

// 本工程支持的操作码集合（Frontier ~ Shanghai 的常用指令，
// 未列出的字节一律视为非法操作码并拒绝）。
var baseOpcodes = map[byte]string{
	0x00: "STOP",
	0x01: "ADD", 0x02: "MUL", 0x03: "SUB", 0x04: "DIV", 0x05: "SDIV",
	0x06: "MOD", 0x07: "SMOD", 0x08: "ADDMOD", 0x09: "MULMOD",
	0x0a: "EXP", 0x0b: "SIGNEXTEND",
	0x10: "LT", 0x11: "GT", 0x12: "SLT", 0x13: "SGT", 0x14: "EQ",
	0x15: "ISZERO", 0x16: "AND", 0x17: "OR", 0x18: "XOR", 0x19: "NOT",
	0x1a: "BYTE", 0x1b: "SHL", 0x1c: "SHR", 0x1d: "SAR",
	0x20: "SHA3",
	0x30: "ADDRESS", 0x31: "BALANCE", 0x32: "ORIGIN", 0x33: "CALLER",
	0x34: "CALLVALUE", 0x35: "CALLDATALOAD", 0x36: "CALLDATASIZE",
	0x37: "CALLDATACOPY", 0x38: "CODESIZE", 0x39: "CODECOPY",
	0x3a: "GASPRICE", 0x3b: "EXTCODESIZE", 0x3c: "EXTCODECOPY",
	0x3d: "RETURNDATASIZE", 0x3e: "RETURNDATACOPY", 0x3f: "EXTCODEHASH",
	0x40: "BLOCKHASH", 0x41: "COINBASE", 0x42: "TIMESTAMP",
	0x43: "NUMBER", 0x44: "DIFFICULTY", 0x45: "GASLIMIT",
	0x46: "CHAINID", 0x47: "SELFBALANCE", 0x48: "BASEFEE",
	0x50: "POP", 0x51: "MLOAD", 0x52: "MSTORE", 0x53: "MSTORE8",
	0x54: "SLOAD", 0x55: "SSTORE", 0x56: "JUMP", 0x57: "JUMPI",
	0x58: "PC", 0x59: "MSIZE", 0x5a: "GAS", 0x5b: "JUMPDEST",
	0x5f: "PUSH0",
	0xf0: "CREATE", 0xf1: "CALL", 0xf2: "CALLCODE", 0xf3: "RETURN",
	0xf4: "DELEGATECALL", 0xf5: "CREATE2", 0xfa: "STATICCALL",
	0xfd: "REVERT", 0xfe: "INVALID", 0xff: "SELFDESTRUCT",
}

// opcodeTable 构建操作码表；未知字节对应 nil。
func opcodeTable() [256]*opcodeInfo {
	var tbl [256]*opcodeInfo
	for b, name := range baseOpcodes {
		tbl[b] = &opcodeInfo{Name: name}
	}
	for i := 1; i <= 32; i++ {
		tbl[0x5f+byte(i)] = &opcodeInfo{Name: fmt.Sprintf("PUSH%d", i), ImmSize: i}
	}
	for i := 1; i <= 32; i++ {
		tbl[0x7f+byte(i)] = &opcodeInfo{Name: fmt.Sprintf("DUP%d", i)}
		tbl[0x8f+byte(i)] = &opcodeInfo{Name: fmt.Sprintf("SWAP%d", i)}
	}
	for i := 0; i <= 4; i++ {
		tbl[0xa0+byte(i)] = &opcodeInfo{Name: fmt.Sprintf("LOG%d", i)}
	}
	return tbl
}
