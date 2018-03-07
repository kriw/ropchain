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
    const auto outputJson = r2cmdj(r2, cmd);
    for(const auto& g : outputJson) {
        const auto opcodes = g.at("opcodes");
        const uint64_t addr = opcodes[0].at("offset");
        auto insns = std::vector<Insn>();
        for(const auto& opcode : opcodes) {
            if(const auto insn = Insn::fromString(opcode.at("opcode"))) {
                insns.push_back(insn.value());
            }
        }
        gadgets.push_back(Gadget(addr, insns));
    }
    return gadgets;
}

std::optional<Gadgets> Frontend::R2::from(const std::string& fileName) {
    auto cmd = std::string("r2 -q0 ") + fileName;
    R2Pipe *r2 = r2p_open(cmd.c_str());
    if(r2 == NULL) {
        return {};
    }
    r2p_cmd(r2, "e rop.len = 2");
    auto gadgets = fromCmd(r2, "\"/R/j ret$\"");
    r2p_cmd(r2, "e rop.len = 3");
    for(auto&& g : fromCmd(r2, "\"/R/j ret$\"")) {
        gadgets.push_back(g);
    }
    std::sort(gadgets.begin(), gadgets.end());
    return gadgets;
}
