#include "solver.h"
#include "config.h"
#include "asm/xor.h"
#include "asm/inc.h"
#include "middle/middle.h"

OptROP Solver::_solve(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        uint64_t base, Cond& cond, Proc& proc, const std::set<char>& avoids) {
    auto ropChains = std::map<RegType::Reg, ROPChain>();
    auto remains = RegSet();
	//Construct ROPChain by itself
    const auto allBits = Util::toBits(Util::map2Regs(dests));
    for(const auto reg : allBits) {
        const auto tmp = findROPChain(reg, dests.at(reg), gadgets,
                RegSet(reg), cond, proc, avoids);
        if(tmp.has_value()) {
            ropChains[reg] = tmp.value();
        } else {
            remains.set(reg);
        }
    }
    if(remains.none()) {
        auto rop = std::accumulate(ropChains.begin(), ropChains.end(), ROPChain(),
			[](const ROPChain& a, const auto& b){return a + b.second;});
        rop.setBaseAddr(base);
        return rop;
    }
	OptROP ans = {};
	//Brute force remains
    auto bits = Util::toBits(remains);
    std::sort(bits.begin(), bits.end());
    do {
        auto rop = ROPChain();
        auto aval = Util::allRegs();
        bool isDone = true;
        //Construct ROPChain with set of registers 'remain'
        for(RegType::Reg reg : bits) {
            const auto tmp = findROPChain(reg, dests.at(reg), gadgets, aval, cond, proc, avoids);
            if(!tmp.has_value()) {
                isDone = false;
                break;
            }
            aval.reset(reg);
            rop += tmp.value();
        }
        if(isDone) {
            ans = Util::optMin(ans, (OptROP)rop);
        }
    } while (next_permutation(bits.begin(), bits.end()));
	if(!ans.has_value()) {
		return {};
	}
	auto rop = std::accumulate(ropChains.begin(), ropChains.end(), ROPChain(),
			[](const ROPChain& a, const auto& b){return a + b.second;});
	rop = ans.value() + rop;
	rop.setBaseAddr(base);
    return (OptROP)rop;
}

//TODO move to asm/pop.cpp
//use reg <- 0; ret; (inc reg)*value
OptROP solveByInc(const RegType::Reg reg, const uint64_t dest, const Gadgets& gadgets, RegSet aval) {
    auto zero = Middle::setVal(reg, 0, gadgets, aval);
    auto inc = Inc::find(reg, gadgets, aval);
    if(dest < 0x1000 && zero.has_value() && inc.has_value()) {
        //zero + inc * dest
        auto tmp = zero.value();
        for(uint64_t i=0; i<dest; i++) {
            tmp += inc.value();
        }
        return tmp;
    }
    return {};
}

//use reg <- somevalue; ret; (inc reg)*(value-someValue)
OptROP solveByPopInc(const RegType::Reg reg, const uint64_t dest, const Gadgets& gadgets,
        const std::set<char>& avoids, const std::vector<uint8_t>& chars, RegSet aval) {
    uint64_t tmpDest = 0;
    const size_t word = Config::Arch::word();
    const uint32_t bits = Config::Arch::bits();
    for(size_t i=0; i<word; i++) {
        const uint8_t byte = (dest >> (bits - (i + 1) * 8)) & 0xff;
        std::vector<uint8_t> filtered;
        std::copy_if(chars.begin(), chars.end(),
                std::back_inserter(filtered),
                [byte](uint8_t x){return x <= byte;});
        if(filtered.size()
                && *std::max_element(filtered.begin(), filtered.end()) == byte) {
            tmpDest = (tmpDest << 8) + byte;
        } else if(filtered.size()) {
            const uint8_t a = *std::max_element(filtered.begin(), filtered.end());
            tmpDest = tmpDest << (bits - i * 8);
            for(size_t j=0; j<word-i; j++) {
                tmpDest += a << j * 8;
            }
            break;
        } else {
            tmpDest--;
            const auto p = [&i, &avoids](uint64_t t){
                for(size_t j = 0; j < i; j++) {
                    const uint8_t x = (t >> j) & 0xff;
                    if(avoids.find(x) != avoids.end()) {
                        return false;
                    }
                }
                return true;
            };
            while(!p(tmpDest) && tmpDest > 0) {
                tmpDest --;
                if(tmpDest <= 0) {
                    return {};
                } else {
                    const uint8_t a = *std::max_element(chars.begin(), chars.end());
                    tmpDest = (tmpDest << (bits - i * 8));
                    for(int j = 0; j < word - i; j++) {
                        tmpDest += a << j * 8;
                    }
                }
            }
            break;
        }
    }
    const auto pop = Middle::setVal(reg, tmpDest, gadgets, aval);
    const auto inc = Inc::find(reg, gadgets, aval);
    if(pop.has_value() && inc.has_value()) {
        //pop + inc * (dest - tmpDest)
        auto ret = pop.value();
        for(int i = 0; i < dest-tmpDest; i++) {
            ret += inc.value();
        }
        return ret;
    }
    return {};
}

//use xor r1, r2
OptROP solveByXor(const RegType::Reg reg, const uint64_t dest, const Gadgets& gadgets,
        const std::set<char>& avoids, const std::vector<uint8_t>& chars, RegSet aval) {
    OptROP rop = {};
    std::array<std::optional<std::pair<uint8_t, uint8_t>>, 0x100> xorTable;
    const std::optional<std::pair<uint8_t, uint8_t>> dummy = {};
    std::fill(xorTable.begin(), xorTable.end(), dummy);
    for(uint8_t a : chars) {
        for(uint8_t b : chars) {
            xorTable[a^b] = std::make_pair(a, b);
        }
    }
    //left ^ right == dest
    uint64_t left, right;
    left = right = 0;
    for(uint32_t i = 0; i < Config::Arch::word(); i++) {
        if(const auto ab = xorTable[(dest >> (i * 8)) & 0xff]) {
            const uint8_t l = ab.value().first;
            const uint8_t r = ab.value().second;
            left = left | l << (i * 8);
            right = right | r << (i * 8);
        } else {
            return {};
        }
    }
    const auto ropLeft = Solver::findROPChain(reg, left, gadgets, aval, {}, {}, avoids);
    if(!ropLeft.has_value()) {
        return {};
    }
    const auto allBits = Util::toBits(aval);
    for(const auto r : allBits) {
        if(const auto _xor = Xor::find(reg, r, gadgets, aval)) {
            aval.reset(reg);
            const auto ropRight =  Middle::setVal(r, right, gadgets, aval);
            aval.set(reg);
            if(ropLeft.has_value() && ropRight.has_value()) {
                const OptROP _rop = ropLeft.value() + ropRight.value() + _xor.value();
                rop = Util::optMin(rop, _rop);
                break;
            }
        }
    }
    return rop;
}

OptROP Solver::solveAvoidChars(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    auto cond = [&avoids](uint64_t value) {
        for(size_t i = 0; i < Config::Arch::word(); i++) {
            const char c = (char)(value & 0xff);
            if(avoids.find(c) != avoids.end()) {
                return false;
            }
            value >>= 8;
        }
        return true;
    };
    Proc proc = [](const RegType::Reg reg, const uint64_t dest,
            const Gadgets& gadgets, const std::set<char>& avoids, RegSet aval) {
        OptROP rop = {};
        if(dest == 0) {
            rop = Util::optMin(rop, Middle::toZero(reg, gadgets, aval));
        }
        //available characters
        std::vector<uint8_t> chars;
        for(uint32_t i = 0; i <= 0xff; i++) {
            if(avoids.find((uint8_t)i) == avoids.end()) {
                chars.push_back((uint8_t)i);
            }
        }
        rop = Util::optMin(rop,
                solveByXor(reg, dest, gadgets,
                    avoids, chars, aval));
        rop = Util::optMin(rop,
                solveByPopInc(reg, dest, gadgets,
                    avoids, chars, aval));
        rop = Util::optMin(rop,
            solveByInc(reg, dest, gadgets, aval));
        return rop;
    };
    auto _gadgets = Gadgets();
    std::copy_if(gadgets.begin(), gadgets.end(), std::back_inserter(_gadgets),
            [&cond, &base](auto &g) {return !g.isUseless && cond(g.addr + base);});
    return _solve(dests, Util::uniqGadgets(_gadgets), base, cond, proc, avoids);
}

OptROP Solver::solveWithGadgets(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    return solveAvoidChars(dests, gadgets, base, avoids);
}

OptROP Solver::solveWithFile(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::set<char>& avoids) {
    auto gadgets = Config::getGadgetLoader()(file);
    if(!gadgets.has_value()) {
        return {};
    }
    return solveWithGadgets(dests, gadgets.value(), base, avoids);
}

OptROP Solver::solveWithMap(const std::map<RegType::Reg, uint64_t>& dests,
        const std::map<uint64_t, std::string> insnStr,
        uint64_t base, const std::set<char>& avoids) {
    Gadgets gadgets;
    for(auto it : insnStr) {
        if(auto g = Util::parseGadgetString(it.first, it.second)) {
            gadgets.push_back(g.value());
        }
    }
    return solveWithGadgets(dests, gadgets, base, avoids);
}

OptROP Solver::findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, std::optional<Cond> cond,
        std::optional<Proc> proc, const std::set<char>& avoids) {
    if(!cond.has_value() || cond.value()(dest)) {
        return Middle::setVal(reg, dest, gadgets, aval);
    }
    if(proc.has_value()) {
        return proc.value()(reg, dest, gadgets, avoids, aval);
    }
    return {};
}
