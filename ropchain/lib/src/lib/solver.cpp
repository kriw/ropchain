#include "solver.h"
#include "arch.h"
#include "config.h"

OptROP Solver::findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc);

OptROP Solver::_solve(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        uint64_t base, Cond& cond, Proc& proc) {
    auto regs = Util::allRegs();

    auto ropChains = std::map<RegType::Reg, ROPChain>();
    auto solvables = RegSet();
    auto remains = RegSet();
	//Construct ROPChain by itself
	{
		const auto allBits = Util::toBits(Util::map2Regs(dests));
		for(const auto reg : *allBits) {
			const auto tmp = findROPChain(reg, dests.at(reg), gadgets, RegSet(RegType::none), cond, proc);
			if(tmp.has_value()) {
				solvables.set(reg);
				ropChains[reg] = tmp.value();
			} else {
                remains.set(reg);
            }
		}
		delete allBits;
	}
    if(remains.none()) {
        auto rop = std::accumulate(ropChains.begin(), ropChains.end(), ROPChain(),
			[](const ROPChain& a, const auto& b){return a + b.second;});
        rop.setBaseAddr(base);
        return rop;
    }
	OptROP ans = {};
	//Brute force remains
	{
		auto bits = Util::toBits(remains);
        std::sort(bits->begin(), bits->end());
        do {
			auto rop = ROPChain();
			auto aval = regs;
			bool isDone = true;
			//Construct ROPChain with set of registers 'remain'
			for(RegType::Reg reg : *bits) {
				aval.reset(reg);
				const auto tmp = findROPChain(reg, dests.at(reg), gadgets, aval, cond, proc);
				if(!tmp.has_value()) {
					isDone = false;
					break;
				}
				rop = rop + tmp.value();
			}
			if(isDone) {
				ans = Util::optMin(ans, (OptROP)rop);
			}
        } while (next_permutation(bits->begin(), bits->end()));
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

OptROP Solver::solveAvoidChars(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    auto cond = [&avoids](uint64_t value) {
        for(size_t i = 0; i < Arch::word(); i++) {
            const char c = (char)(value & 0xff);
            if(avoids.find(c) != avoids.end()) {
                return false;
            }
            value >>= 8;
        }
        return true;
    };
    Proc proc = [](const RegType::Reg reg, const uint64_t base,
            const Gadgets& gadgets, RegSet availables) {
        //TODO
        return ROPChain(Gadget(0, std::vector<Insn>()));
    };
    return _solve(dests, gadgets, base, cond, proc);
}

OptROP Solver::solveWithGadgets(const std::map<RegType::Reg, uint64_t>& dests, const Gadgets& gadgets,
        const uint64_t base, const std::set<char>& avoids) {
    return solveAvoidChars(dests, gadgets, base, avoids);
}

OptROP Solver::solveWithFile(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::set<char>& avoids) {
    auto gadgets = Config::getGadgetLoader()(file);
    printf("%p\n", Config::getGadgetLoader());
    // for(auto g : gadgets.value()) {
    //     std::cout << g.toString() << std::endl;
    // }
    if(!gadgets.has_value()) {
        return {};
    }
    return solveWithGadgets(dests, gadgets.value(), base, avoids);
}

OptROP Solver::findROPChain(const RegType::Reg reg, const uint64_t dest,
        const Gadgets& gadgets, RegSet aval, Cond& cond, Proc& proc) {
    if(cond(dest)) {
        return Middle::setVal(reg, dest, gadgets, aval);
    }
    return proc(reg, dest, gadgets, aval);
}
