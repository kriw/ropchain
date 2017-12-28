#pragma once
#include <string>
#include <vector>
#include <optional>
#include <set>
#include <variant>
#include <cstdio>
#include <cstring>
#include "regs.h"

typedef std::string Mnem;
typedef std::variant<uint64_t, RegType::Reg> Opcode;
template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

typedef struct Insn {
    Mnem mnem;
    std::vector<Opcode> ops;
    bool operator==(const struct Insn& insn) const {
		if(ops.size() != insn.ops.size()) {
			return false;
		}
		for(int i=0; i<ops.size(); i++) {
			if(std::visit(overloaded {
						[](uint64_t a, RegType::Reg b) {return false;},
						[](RegType::Reg a, uint64_t b) {return false;},
						[](uint64_t a, uint64_t b) {return a == b;},
						[](RegType::Reg a, RegType::Reg b) {return a == b;},
						}, ops[i], insn.ops[i])) {
				return false;
			}
		}
        return mnem == insn.mnem;
    }
    static Opcode strToOpcode(std::string s) {
        //TODO
        return (uint64_t)0;
    }
    static Insn fromString(std::string opcode) {
        char _mnem[0x100];
        char *_ops = new char[0x100];
        char * const p = _ops;
        sscanf(opcode.c_str(), "%s %[^\n\t]", _mnem, _ops);
        Mnem mnem = std::string(mnem);
        auto ops = std::vector<Opcode>();
        for(char *tmp = strchr(_ops, ','); tmp; _ops = tmp + 1) {
            auto op = strToOpcode(std::string(tmp + 1));
            ops.push_back(op);
        }
        delete p;
        return Insn{.mnem = mnem, .ops = ops};
    }
	std::string toString() const {
		//FIXME replace sprintf with safe function
		std::string ret(0x100, '\0');
		auto toStr = [](Opcode op){return std::visit(overloaded {
					[](uint64_t x){return std::to_string(x);},
					[](RegType::Reg x){return std::to_string(x);},
				}, op);};
		sprintf((char *)ret.c_str(), "%s %s, %s\n", mnem.c_str(), toStr(ops[0]).c_str(), toStr(ops[1]).c_str());
		return ret;
	}
    bool operator!=(const struct Insn& insn) {
        return !(*this == insn);
    }
} Insn;

typedef std::vector<Insn> Insns;

class Gadget {
public:
    Gadget(uint64_t _addr, std::vector<Insn> _insns);
    bool isChanged(const RegType::Reg reg) const;
    bool isAvailable(const RegSet& reg) const;
    std::string toString() const;
    bool operator==(const Gadget& gadget) const;
    bool operator!=(const Gadget& gadget) const;
    const std::vector<Insn> getInsns() const;
	uint32_t getUseStack() const;
	uint64_t getAddr() const;
private:
    std::vector<Insn> insns;
    uint64_t addr;
    //how many byte will be added to esp/rsp
    uint32_t useStack;
    //registers which will be changed its value
    RegSet changedRegs;
};

typedef std::optional<Gadget> OptGadget;
typedef std::vector<Gadget> Gadgets;
typedef std::pair<Gadget, uint64_t> GadgetWithValue;
