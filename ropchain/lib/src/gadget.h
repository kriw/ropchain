#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <set>
#include <cstdio>
#include "insn.h"

class Gadget {
public:
    Gadget(uint64_t _addr, std::vector<Insn> _insns);
    bool isChanged(const RegType::Reg reg) const;
    bool isAvailable(const RegSet& reg) const;
    std::string toString() const;
    Gadget& operator=(const Gadget& gadget) const;
    bool operator==(const Gadget& gadget) const;
    bool operator!=(const Gadget& gadget) const;
    const std::vector<Insn> getInsns() const;
	uint32_t getUseStack() const;
	uint64_t getAddr() const;
private:
    const std::vector<Insn> insns;
    const uint64_t addr;
    //how many byte will be added to esp/rsp
    const uint32_t useStack;
    //registers which will be changed its value
    const RegSet changedRegs;
};

typedef std::optional<Gadget> OptGadget;
typedef std::vector<Gadget> Gadgets;
typedef std::pair<Gadget, uint64_t> GadgetWithValue;
