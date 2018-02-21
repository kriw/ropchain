#include "gadget.h"
#include "util.h"

Gadget::Gadget(const uint64_t _addr, const std::vector<Insn>& _insns)
:   insns(_insns),
    addr(_addr),
    useStack(Util::calcUseStack(_insns)),
    changedRegs(Util::listChangedRegs(insns)),
    hash(calcHash(_insns))
{
}

Gadget& Gadget::operator=(const Gadget& gadget) {
    if(this != &gadget) {
        (uint64_t&)addr = gadget.addr;
        (std::vector<Insn>&)insns = gadget.insns;
        (uint64_t&)useStack = gadget.useStack;
        (RegSet&)changedRegs = gadget.changedRegs;
    }
    return *this;
}

std::string Gadget::toString() const {
    auto ss = std::vector<std::string>(insns.size());
    std::transform(insns.begin(), insns.end(), ss.begin(),
            [](const auto& x){return x.toString();});
    return Util::join(ss, "\n");
}

bool Gadget::operator==(const Gadget& gadget) const {
    const auto _insns = gadget.insns;
    if(hash != gadget.hash) {
        return false;
    }
    if(insns.size() != _insns.size()) {
        return false;
    }
    return insns == _insns;
}

bool Gadget::operator!=(const Gadget& gadget) const {
    return !(*this == gadget);
}

bool Gadget::operator<(const Gadget& gadget) const {
    return useStack < gadget.useStack;
}

bool Gadget::isChanged(const RegType::Reg reg) const {
    return changedRegs.test(reg);
}

bool Gadget::isAvailable(const RegSet& rs) const {
    return (changedRegs & rs) == changedRegs;
}

size_t Gadget::calcHash(const std::vector<Insn> insns) {
    size_t h = 0;
    for(const auto& insn : insns) {
        h = (h << 1) ^ insn.hash;
    }
    return h;
}
