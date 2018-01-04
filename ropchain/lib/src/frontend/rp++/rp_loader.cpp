#include <sstream>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <string>
#include "rp_loader.h"
#include "../../util.h"

//FIXME
const std::string scriptPath = "./src/frontend/rp++/rp_script.sh";

std::optional<std::string> _exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
    if (!pipe) return {};
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}

std::optional<Gadgets> Frontend::RPP::from(const std::string& fileName) {
    std::optional<std::string> gadgetsStr = _exec(scriptPath.c_str());
    if(!gadgetsStr.has_value()) {
        return {};
    }
    std::stringstream ss(gadgetsStr.value());
    std::string s;
    Gadgets gadgets;
    //TODO trim strings
    while(getline(ss, s)) {
        size_t sz = 2;
        const uint64_t addr = stoull(s.substr(0, s.find(':')), &sz, 16);
        std::vector<Insn> insns;
        s = s.substr(s.find(' '));
        auto opcodes = Util::split(s, ';');
        for(const auto& opcode : opcodes) {
            std::vector<Insn> insns;
            auto insn = Insn::fromString(opcode);
            if(insn.has_value()) {
                insns.push_back(insn.value());
            }
        }
        gadgets.push_back(Gadget(addr, insns));
    }
    return gadgets;
}
