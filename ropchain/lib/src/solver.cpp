#include <optional>
#include <map>
#include <functional>
#include <numeric>
#include "ropchain.h"
#include "gadget.h"
#include "util.h"
#include "middle/middle.h"

typedef const std::function<bool(uint64_t)>& Cond;
typedef const std::function<OptROP(const RegType::Reg, const uint64_t,
        const Gadgets&, RegSet)> Proc;

OptROP findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc);

OptROP _solve(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        uint64_t base, Cond& cond, Proc& proc) {
    auto regs = Util::allRegs();

    auto ropChains = std::map<RegType::Reg, ROPChain>();
    auto solvables = RegSet();
    auto remains = regs;
	//Construct ROPChain by itself
	{
		const auto allBits = Util::toBits(regs);
		for(auto reg : *allBits) {
			auto tmp = findROPChain(reg, dests.at(reg), gadgets, RegSet(RegType::none), cond, proc);
			if(tmp.has_value()) {
				solvables.set(reg);
				remains.reset(reg);
				ropChains[reg] = tmp.value();
			}
		}
		delete allBits;
	}
	std::vector<RegType::Reg> *bits = nullptr;
	OptROP ans = {};
	//Brute force remains
	{
		auto bits = Util::toBits(remains);
		while (next_permutation(bits->begin(), bits->end())) {
			auto rop = ROPChain();
			auto aval = regs;
			bool isDone = true;
			//Construct ROPChain with set of registers 'remain'
			for(RegType::Reg reg : *bits) {
				aval.reset(reg);
				auto tmp = findROPChain(reg, dests.at(reg), gadgets, aval, cond, proc);
				if(!tmp.has_value()) {
					isDone = false;
					break;
				}
				rop = rop + tmp.value();
			}
			if(isDone) {
				ans = Util::optMin(ans, (OptROP)rop);
			}
		}
		delete bits;
	}
	if(!ans.has_value()) {
		return {};
	}
	auto rop = std::accumulate(ropChains.begin(), ropChains.end(), ROPChain(),
			[](const ROPChain& a, const auto& b){return a + b.second;});
	rop = rop + ans.value();
	rop.setBaseAddr(base);
    return (OptROP)rop;
}

OptROP solveAvoidChars(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    //TODO
    auto cond = [](uint64_t value) {
        return false;
    };
    Proc proc = [](const RegType::Reg reg, const uint64_t base,
            const Gadgets& gadgets, RegSet availables) {
        return ROPChain(Gadget(0, std::vector<Insn>()));
    };
    return _solve(dests, gadgets, base, cond, proc);
}

OptROP solveWithGadgets(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    return solveAvoidChars(dests, gadgets, base, avoids);
}

OptROP solveWithFile(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::set<char>& avoids) {
    auto gadgets = Util::loadGadgets(file);
    return solveWithGadgets(dests, gadgets, base, avoids);
}

OptROP findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc) {
    if(cond(dest)) {
        Middle::setVal(reg, dest, gadgets, aval);
    }
    return proc(reg, dest, gadgets, aval);
}

int main() {
    printf("Hello, world!\n");
    return 0;
}
