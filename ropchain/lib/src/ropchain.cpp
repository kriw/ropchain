#include <variant>
#include "ropchain.h"
#include "arch.h"
#include "util.h"

ROPChain::ROPChain()
: baseAddr(0)
{
}

ROPChain::ROPChain(const ROPElem elem)
: baseAddr(0)
{
	ROPElems es = std::visit([](const auto& e) {
			using T = std::decay_t<decltype(e)>;
			if constexpr(std::is_same_v<T, Gadget>) {
				return ROPElems({std::string(e.useStack, 'A')});
			} else if constexpr(std::is_same_v<T, GadgetWithValue>) {
				auto s = std::string(e.first.useStack - Arch::word(), 'A');
				return ROPElems({e, s});
			}
			return ROPElems({e});
		}, elem);
	for(auto& e : es) {
		elems.push_back(e);
	}
}

void ROPChain::setBaseAddr(const uint64_t addr) {
    baseAddr = addr;
}

void ROPChain::dump() const {
	for(auto& elem : elems) {
		std::visit([](auto&& e){
			using T = std::decay_t<decltype(e)>;
			if constexpr(std::is_same_v<T, Gadget>) {
				std::cout << e.toString() << std::endl;
			} else if constexpr(std::is_same_v<T, GadgetWithValue>) {
				std::cout << e.first.toString() << std::endl;
				std::cout << e.second << std::endl;
			} else if constexpr(std::is_same_v<T, std::string>) {
				std::cout << e << std::endl;
			} else if constexpr(std::is_same_v<T, uint64_t>) {
				std::cout << e << std::endl;
			}
        }, elem);
	}
}

std::string ROPChain::payload() const {
	std::string payload;
	for(auto& elem : elems) {
		std::string s = std::visit([&](auto&& e){
			using T = std::decay_t<decltype(e)>;
			if constexpr(std::is_same_v<T, Gadget>) {
				return Util::pack(e.addr + baseAddr);
			} else if constexpr(std::is_same_v<T, GadgetWithValue>) {
				return Util::pack(e.first.addr + baseAddr) + Util::pack(e.second);
			} else if constexpr(std::is_same_v<T, std::string>) {
				return e;
			} else if constexpr(std::is_same_v<T, uint64_t>) {
				return Util::pack(e);
			}
			}, elem);
		payload += s;
	}
    return payload;
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
    auto r = *this;
    r += rop;
	return r;
}

ROPChain ROPChain::operator+=(const ROPChain& rop) {
    const auto e = rop.getElems();
    std::copy(e.begin(), e.end(), std::back_inserter(elems));
    return *this;
}

bool ROPChain::operator<(const ROPChain& rop) const {
    return length() < rop.length();
}
