#include <cstdio>
#include <vector>
#include "r2_loader.h"
#include "../misc/json.hpp"

using nlohmann::json;

std::string Frontend::test(const char *file) {
	R2Pipe *r2 = r2p_open(file);
	if (r2) {
		auto ret = r2cmdj (r2, "\"/R/j pop rax;ret\"");
		r2p_close (r2);
		return ret;
	}
	return "";
}

Gadget Frontend::fromCmd(R2Pipe *r2, const std::string& cmd) {
    auto res = r2cmdj(r2, cmd);
    auto opcodes = res.at("opcodes");
    uint64_t addr = opcodes[0].at("offset");
    auto insns = std::vector<Insn>();
    for(const auto& opcode : opcodes) {
        auto insn = Insn::fromString(opcode.at("opcode"));
        insns.push_back(insn);
    }
    return Gadget(addr, insns);
}

std::optional<Gadgets> Frontend::fromR2(const std::string& fileName) {
    R2Pipe *r2 = r2p_open("r2 -q0 /bin/ls");
    if(r2 == NULL) {
        return {};
    }
    //TODO
    return Gadgets({fromCmd(r2, "\"/R/j pop rax;ret\"")});
}
