#include "ropchain.h"

ROPChain::ROPChain() {
    //TODO
}

ROPChain::ROPChain(const ROPElem elem)
: baseAddr(0) {
    elems = {elem};
}

ROPChain::ROPChain(const ROPElems _elems)
: baseAddr(0) {
    //TODO
    elems = _elems;
}

void ROPChain::append(ROPElem elem) {
   //TODO
   //consider about useStack
   elems.push_back(elem);
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

void ROPChain::setBaseAddr(const uint64_t addr) {
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
    auto es = ropchain.getElems();
    es.insert(std::end(elems), std::begin(es), std::end(es));
}

ROPElems ROPChain::getElems() const {
    return elems;
}

size_t ROPChain::length() const {
    //TODO
    return 0;
}

ROPChain ROPChain::operator+(const ROPChain& rop) const {
	auto e1 = elems;
	auto e2 = rop.getElems();
	e1.insert(e1.end(), e2.begin(), e2.end());
	return ROPChain(e1);
}
bool ROPChain::operator<(const ROPChain& rop) const {
    //TODO
    return true;
}
