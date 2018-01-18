#pragma once
#include <cstring>
#include <variant>
#include <optional>
#include <vector>
#include <iostream>
#include <utility>
#include "regs.h"

typedef std::pair<RegType::Reg, uint64_t> RegOffset;
typedef const std::variant<uint64_t, RegOffset> MemOp;
typedef const std::string Mnem;
typedef std::variant<uint64_t, RegType::Reg, MemOp> Operand;

struct Insn {
    const Mnem mnem;
    const std::vector<Operand> ops;
    Insn(Mnem _mnem, std::vector<Operand> _ops);
    Insn& operator=(const Insn&) const;
    bool operator==(const Insn& insn) const;
    bool operator!=(const Insn& insn) const;
    std::optional<std::string> toString() const;
    static std::optional<Operand> strToOperand(std::string s);
    static std::optional<Insn> fromString(const std::string& opcode);
    static std::optional<MemOp> memRef(const Operand& op, uint64_t offset);
};

typedef std::vector<Insn> Insns;
