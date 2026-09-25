// Package bytecode decodes raw EVM bytecode into instructions and splits
// them into basic blocks. Malformed inputs are rejected with typed,
// distinguishable errors rather than analyzed as valid contracts.
package bytecode

import (
	"encoding/binary"
	"fmt"

	"github.com/highcumontoa/evm-bytecode-audit-go/opcodes"
)

// RejectKind categorizes why a bytecode input was rejected.
type RejectKind string

const (
	// RejectEmpty means the input had zero length.
	RejectEmpty RejectKind = "empty_bytecode"
	// RejectInvalidOpcode means an undefined (or INVALID) opcode byte was
	// encountered during the linear sweep.
	RejectInvalidOpcode RejectKind = "invalid_opcode"
	// RejectTruncatedImmediate means a PUSHn ran past the end of input.
	RejectTruncatedImmediate RejectKind = "truncated_immediate"
	// RejectJumpOutOfBounds means a statically determinable jump target
	// points outside the bytecode.
	RejectJumpOutOfBounds RejectKind = "jump_target_out_of_bounds"
	// RejectJumpNotDest means a statically determinable jump target does
	// not point at a JUMPDEST opcode.
	RejectJumpNotDest RejectKind = "jump_target_not_jumpdest"
)

// RejectError is the typed error returned for malformed contract input.
type RejectError struct {
	Kind   RejectKind
	Offset int // byte offset where the problem was detected (-1 when N/A)
	Detail string
}

func (e *RejectError) Error() string {
	if e.Offset >= 0 {
		return fmt.Sprintf("bytecode rejected (%s) at offset %d: %s", e.Kind, e.Offset, e.Detail)
	}
	return fmt.Sprintf("bytecode rejected (%s): %s", e.Kind, e.Detail)
}

// DecodedContract is a successfully decoded contract. The stored Code is a
// defensive copy; callers may reuse or mutate the buffer passed to Decode.
type DecodedContract struct {
	Name         string
	Code         []byte
	Instructions []opcodes.Instruction
}

// Decode validates and decodes raw EVM bytecode. A non-nil error is always
// a *RejectError, and no partial result is returned on rejection.
//
// Validation order (first failure wins, lowest offset):
//  1. empty input;
//  2. unknown / INVALID opcode during the linear sweep;
//  3. PUSHn immediate truncated by end of input;
//  4. statically determinable jump targets (PUSHk <target> immediately
//     followed by JUMP/JUMPI) pointing out of bounds;
//  5. such targets not landing on JUMPDEST.
//
// Jump targets supplied dynamically (not via an adjacent PUSH) cannot be
// statically resolved and are intentionally not rejected.
func Decode(name string, code []byte) (*DecodedContract, error) {
	if len(code) == 0 {
		return nil, &RejectError{Kind: RejectEmpty, Offset: -1, Detail: "zero-length bytecode is not a valid contract"}
	}

	insts := make([]opcodes.Instruction, 0, len(code))
	for off := 0; off < len(code); {
		b := opcodes.OpCode(code[off])
		if !opcodes.IsKnown(b) {
			return nil, &RejectError{
				Kind:   RejectInvalidOpcode,
				Offset: off,
				Detail: fmt.Sprintf("opcode 0x%02x has no defined mnemonic", byte(b)),
			}
		}
		info := opcodes.Lookup(b)
		if info.Immediate > 0 {
			end := off + 1 + info.Immediate
			if end > len(code) {
				missing := end - len(code)
				return nil, &RejectError{
					Kind:   RejectTruncatedImmediate,
					Offset: off,
					Detail: fmt.Sprintf("%s needs %d immediate byte(s), %d missing", info.Name, info.Immediate, missing),
				}
			}
			imm := make([]byte, info.Immediate)
			copy(imm, code[off+1:end])
			insts = append(insts, opcodes.Instruction{Offset: off, Op: b, Immediate: imm})
			off = end
			continue
		}
		insts = append(insts, opcodes.Instruction{Offset: off, Op: b})
		off++
	}

	if err := validateStaticJumps(code, insts); err != nil {
		return nil, err
	}

	stored := make([]byte, len(code))
	copy(stored, code)
	return &DecodedContract{Name: name, Code: stored, Instructions: insts}, nil
}

// validateStaticJumps checks every PUSHk/JUMP adjacency. The immediate is
// interpreted as a big-endian unsigned target, matching EVM PUSH semantics.
func validateStaticJumps(code []byte, insts []opcodes.Instruction) error {
	for i := 1; i < len(insts); i++ {
		cur := insts[i]
		if cur.Op != opcodes.JUMP && cur.Op != opcodes.JUMPI {
			continue
		}
		prev := insts[i-1]
		if !opcodes.IsPush(prev.Op) || len(prev.Immediate) == 0 {
			continue // dynamic target: outside the statically decidable subset
		}
		target := int(decodePaddedUint(prev.Immediate))
		if target >= len(code) {
			return &RejectError{
				Kind:   RejectJumpOutOfBounds,
				Offset: cur.Offset,
				Detail: fmt.Sprintf("%s target %d exceeds bytecode length %d", opcodes.Lookup(cur.Op).Name, target, len(code)),
			}
		}
		if opcodes.OpCode(code[target]) != opcodes.JUMPDEST {
			return &RejectError{
				Kind:   RejectJumpNotDest,
				Offset: cur.Offset,
				Detail: fmt.Sprintf("%s target %d does not point at JUMPDEST (found 0x%02x)", opcodes.Lookup(cur.Op).Name, target, code[target]),
			}
		}
	}
	return nil
}

// decodePaddedUint interprets a PUSH immediate (1..32 bytes) as unsigned.
func decodePaddedUint(b []byte) uint64 {
	if len(b) > 8 {
		// Targets beyond 2^63 cannot exist in any bytecode this tool will
		// ever decode, so folding the high bytes is sufficient for the
		// bounds comparison performed here.
		return binary.BigEndian.Uint64(b[len(b)-8:])
	}
	var padded [8]byte
	copy(padded[8-len(b):], b)
	return binary.BigEndian.Uint64(padded[:])
}
