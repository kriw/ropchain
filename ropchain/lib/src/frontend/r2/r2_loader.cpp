#include <cstdio>
#include <iostream>
#include <vector>
#include "r2_loader.h"
#include "../../misc/json.hpp"

using nlohmann::json;

json r2cmdj(R2Pipe *r2, const std::string& cmd) {
    auto s = r2p_cmd(r2, cmd.c_str());
    const int n = strlen(s);
    char *buf = new char[n + 3];
    buf[0] = '[';
    strcpy(buf+1, s);
    buf[n+1] = ']';
    buf[n+2] = '\0';
    auto out = json::parse(buf);
    delete[] buf;
    return out;
}

Gadgets Frontend::R2::fromCmd(R2Pipe *r2, const std::string& cmd) {
    auto gadgets = Gadgets();
    auto outputJson = r2cmdj(r2, cmd);
    for(const auto& g : outputJson) {
        auto opcodes = g.at("opcodes");
        const uint64_t addr = opcodes[0].at("offset");
        auto insns = std::vector<Insn>();
        for(const auto& opcode : opcodes) {
            auto insn = Insn::fromString(opcode.at("opcode"));
            if(insn.has_value()) {
                insns.push_back(insn.value());
            }
        }
        gadgets.push_back(Gadget(addr, insns));
    }
    return gadgets;
}

std::optional<Gadgets> Frontend::R2::from(const std::string& fileName) {
    R2Pipe *r2 = r2p_open("r2 -q0 /bin/ls");
    if(r2 == NULL) {
        return {};
    }
    r2p_cmd(r2, "e rop.len = 2");
    //TODO more gadgets
    return fromCmd(r2, "\"/R/j ret$\"");
}
