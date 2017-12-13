#include "ropchain.h"

ROPChain::ROPChain(Gadget gadget, uint64_t value, uint64_t base) {
}

void ROPChain::append(Gadget gadget, uint64_t value) {
   //TODO
// self.gadgets.append(gadget)
// payload = ''
// if value is None:
//     payload = 'A' * gadget.useStack
// else:
//     payload = pack(value) + 'A' * (gadget.useStack - arch.word())
//
// if len(payload) > 0:
//     self.gadgets.append(payload);
}

void ROPChain::setBaseAddr(uint64_t addr) {
    baseAddr = addr;
}

void ROPChain::dump() const {
    //TODO
    std::cout << "TODO" << std::endl;
}

std::string ROPChain::payload() const {
    //TODO
    return "TODO";
}

void ROPChain::chain(const ROPChain& ropchain) {
    const auto gs = ropchain.getGadgets();
    gadgets.insert(std::end(gadgets), std::begin(gs), std::end(gs));
}

Gadgets ROPChain::getGadgets() const {
    return gadgets;
}

size_t ROPChain::length() {
    //TODO
    return 0;
}

namespace GadgetUtil {
    ROPChain toROP(const Gadget& gadget) {
        return ROPChain(gadget, 0, 0);
    }
    OptROP toOptROP(const optGadget& gadget) {
        if(gadget.has_value()) {
            return toROP(gadget.value());
        }
        return {};
    }
}
