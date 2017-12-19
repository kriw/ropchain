#include "gadget.h"
#include "util.h"

Gadget::Gadget(uint64_t _addr, std::vector<Insn> _insns) {
    addr = _addr;
    insns = _insns;
    useStack = Util::calcUseStack(insns);
    changedRegs = Util::listChangedRegs(insns);
}

std::string Gadget::toString() const {
	std::string ret = "";
	for(auto insn : insns) {
		ret += insn.toString() + "\n";
	}
    return ret;
}

bool Gadget::operator==(const Gadget& gadget) const {
    const auto _insns = gadget.getInsns();
    if(insns.size() != _insns.size()) {
        return false;
    }
    return insns == _insns;
}

bool Gadget::operator!=(const Gadget& gadget) const {
    return !(*this == gadget);
}

bool Gadget::isChanged(const RegType::Reg reg) const {
    return changedRegs.test(reg);
}

bool Gadget::isAvailable(const RegSet& rs) const {
    return (changedRegs & rs) == rs;
}

uint32_t Gadget::getUseStack() const {
	return useStack;
}

const std::vector<Insn> Gadget::getInsns() const {
    return insns;
}

uint64_t Gadget::getAddr() const {
	return addr;
}
