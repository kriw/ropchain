#include <variant>
#include "ropchain.h"
#include "config.h"
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
                //In case of not pop gadgets
				return ROPElems({e, std::string(e.useStack, 'A')});
			} else if constexpr(std::is_same_v<T, GadgetWithValue>) {
                //In case of pop gadgets
				auto s = std::string(e.first.useStack - Config::Arch::word(), 'A');
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
				std::cout << Util::intToHex(e.second) << std::endl;
			} else if constexpr(std::is_same_v<T, std::string>) {
				std::cout << e << std::endl;
			} else if constexpr(std::is_same_v<T, uint64_t>) {
				std::cout << Util::intToHex(e) << std::endl;
			}
        }, elem);
	}
}

std::string ROPChain::payload() const {
	std::string payload;
	for(auto& e : elems) {
		payload += std::visit([&](auto&& e){
                using T = std::decay_t<decltype(e)>;
                if constexpr(std::is_same_v<T, Gadget>) {
                    return Util::pack(e.addr + baseAddr);
                } else if constexpr(std::is_same_v<T, GadgetWithValue>) {
                    return Util::pack(e.first.addr + baseAddr) + Util::pack(e.second);
                } else if constexpr(std::is_same_v<T, std::string>) {
                    return e;
                } else if constexpr(std::is_same_v<T, uint64_t>) {
                    return Util::pack(e);
                } else {
                    return std::string();
                }
            }, e);
	}
    return payload;
}

void ROPChain::chain(const ROPChain& ropchain) {
    auto es = ropchain.getElems();
    std::copy(es.begin(), es.end(), std::back_inserter(elems));
}

ROPElems ROPChain::getElems() const {
    return elems;
}

//unit: byte
size_t ROPChain::length() const {
    return elems.size() * Config::Arch::word();
}

ROPChain ROPChain::operator+(const ROPChain& rop) const {
    auto r = *this;
    r += rop;
	return r;
}

ROPChain ROPChain::operator+=(const ROPChain& rop) {
    this->chain(rop);
    return *this;
}

bool ROPChain::operator<(const ROPChain& rop) const {
    return length() < rop.length();
}
