#pragma once
#include <cstring>
#include <variant>
#include <optional>
#include <vector>
#include <iostream>
#include "regs.h"

typedef const std::string Mnem;
typedef std::variant<uint64_t, RegType::Reg> Opcode;

template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

class Insn {
public:
    const Mnem mnem;
    const std::vector<Opcode> ops;
    Insn(Mnem _mnem, std::vector<Opcode> _ops);
    Insn& operator=(const Insn&) const;
    bool operator==(const Insn& insn) const;
    bool operator!=(const Insn& insn) const;
    std::optional<std::string> toString() const;
    static std::optional<Opcode> strToOpcode(std::string s);
    static std::optional<Insn> fromString(const std::string& opcode);
};

typedef std::vector<Insn> Insns;
