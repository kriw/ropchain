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
    //FIXME change some accessors to private
public:
    Insn(Mnem _mnem, std::vector<Opcode> _ops);
    Mnem mnem;
    std::vector<Opcode> ops;
    Insn& operator=(const Insn&);
    bool operator==(const Insn& insn) const;
    static Opcode strToOpcode(std::string s);
    static std::optional<Insn> fromString(const std::string& opcode);
    std::optional<std::string> toString() const;
    bool operator!=(const Insn& insn);
};

typedef std::vector<Insn> Insns;
