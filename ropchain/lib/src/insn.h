#pragma once
#include <cstring>
#include <variant>
#include <optional>
#include <vector>
#include <iostream>
#include "regs.h"

typedef const std::string Mnem;
typedef std::variant<uint64_t, RegType::Reg> Operand;

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

class Insn {
public:
    const Mnem mnem;
    const std::vector<Operand> ops;
    Insn(Mnem _mnem, std::vector<Operand> _ops);
    Insn& operator=(const Insn&) const;
    bool operator==(const Insn& insn) const;
    bool operator!=(const Insn& insn) const;
    std::optional<std::string> toString() const;
    static std::optional<Operand> strToOperand(std::string s);
    static std::optional<Insn> fromString(const std::string& opcode);
};

typedef std::vector<Insn> Insns;
