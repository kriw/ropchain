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
    const size_t hash;
    Insn(Mnem _mnem, std::vector<Operand> _ops);
    Insn& operator=(const Insn&);
    bool operator==(const Insn& insn) const;
    bool operator!=(const Insn& insn) const;
    std::string toString() const;
    static size_t calcHash(const Mnem mnem, const std::vector<Operand> ops);
    static std::optional<Operand> strToOperand(const std::string& s);
    static std::optional<Insn> fromString(const std::string& opcode);
    static std::optional<MemOp> memRef(const Operand& op, uint64_t offset);
};

typedef std::vector<Insn> Insns;

namespace std {
    template <> struct hash<Operand> {
        size_t operator()(const Operand& x) const {
            //TODO
            if(const auto _x = get_if<uint64_t>(&x)) {
                return *_x;
            }
            return 1;
        }
    };
    template <> struct hash<std::vector<Operand>> {
        size_t operator()(const std::vector<Operand>& xs) const {
            //TODO
            size_t h = 0;
            for(auto& x : xs) {
                h += hash<Operand>{}(x);
            }
            return h;
        }
    };
}