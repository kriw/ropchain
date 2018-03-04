#include "gadget.h"
#include <sstream>
#include "util.h"

//XXX
Gadget::Gadget()
:   insns(std::vector<Insn>()),
    addr(0),
    useStack(0),
    changedRegs(RegSet()),
    hash(0),
    isUseless(calcIsUseless(insns))
{
}

Gadget::Gadget(const uint64_t _addr, const std::vector<Insn>& _insns)
:   insns(_insns),
    addr(_addr),
    useStack(Util::calcUseStack(_insns)),
    changedRegs(Util::listChangedRegs(insns)),
    hash(calcHash(_insns)),
    isUseless(calcIsUseless(_insns))
{
}

Gadget& Gadget::operator=(const Gadget& gadget) {
    if(this != &gadget) {
        (uint64_t&)addr = gadget.addr;
        (std::vector<Insn>&)insns = gadget.insns;
        (uint64_t&)useStack = gadget.useStack;
        (RegSet&)changedRegs = gadget.changedRegs;
        (size_t&)hash = gadget.hash;
        (bool&)isUseless = gadget.isUseless;
    }
    return *this;
}

std::string Gadget::toString() const {
    auto ss = std::vector<std::string>(insns.size());
    std::transform(insns.begin(), insns.end(), ss.begin(),
            [](const auto& x){return x.toString();});
    return Util::intToHex(addr) + ":\t " + Util::join(ss, "; ");
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
    //XXX
    return !isUseless && (changedRegs & rs) == changedRegs;
}

//XXX
bool Gadget::calcIsUseless(std::vector<Insn> insns) {
    if(insns.size() == 0) {
        return false;
    }
    const auto changed = Util::listChangedRegs(insns[0]);
    const auto dummy = RegSet();
    //XXX Very slow
    for(int i = 1; i < insns.size(); i++) {
        if((changed & Util::listChangedRegs(insns[i])) != dummy) {
            return true;
        }
    }
    return false;
}

size_t Gadget::calcHash(const std::vector<Insn> insns) {
    size_t h = 0;
    for(const auto& insn : insns) {
        h = (h << 1) ^ insn.hash;
    }
    return h;
}
