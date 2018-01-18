#include "gadget.h"
#include "util.h"

Gadget::Gadget(uint64_t _addr, std::vector<Insn> _insns)
:   insns(_insns),
    addr(_addr),
    useStack(Util::calcUseStack(_insns)),
    changedRegs(Util::listChangedRegs(insns))
{
}

Gadget& Gadget::operator=(const Gadget& gadget) const {
    auto& a = std::move((const Gadget)Gadget(gadget.addr, gadget.insns));
    return (Gadget &)a;
}

std::string Gadget::toString() const {
    auto ss = std::vector<std::string>(insns.size());
    std::transform(insns.begin(), insns.end(), ss.begin(),
            [](const auto& x){return x.toString().value();});
    return Util::join(ss, "\n");
}

bool Gadget::operator==(const Gadget& gadget) const {
    const auto _insns = gadget.insns;
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
