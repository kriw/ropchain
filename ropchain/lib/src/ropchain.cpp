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

void ROPChain::dump() {
    //TODO
}

char *ROPChain::payload() {
    //TODO
    return NULL;
}

void ROPChain::chain(const ROPChain& ropchain) {
    //TODO
}

size_t ROPChain::length() {
    //TODO
    return 0;
}
