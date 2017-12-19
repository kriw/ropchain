#include <variant>
#include "ropchain.h"
#include "arch.h"

ROPChain::ROPChain()
: baseAddr(0)
{
}

ROPChain::ROPChain(const ROPElem elem)
: baseAddr(0)
, elems{{elem}}
{
}

ROPChain::ROPChain(const ROPElems _elems)
: baseAddr(0)
, elems{_elems}
{
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
	for(auto& elem : elems) {
		std::visit(overloaded {
				[](uint64_t e){std::cout << e << std::endl;},
				[](const Gadget& e){std::cout << e.toString() << std::endl;},
				}, elem);
	}
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

//unit: byte
size_t ROPChain::length() const {
    return elems.size() * Arch::word();
}

ROPChain ROPChain::operator+(const ROPChain& rop) const {
	auto e1 = elems;
	auto e2 = rop.getElems();
	e1.insert(e1.end(), e2.begin(), e2.end());
	return ROPChain(e1);
}
bool ROPChain::operator<(const ROPChain& rop) const {
    return this->length() < rop.length();
}
