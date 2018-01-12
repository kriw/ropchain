#include <utility>
#include "insn.h"
#include "util.h"

Insn::Insn(Mnem _mnem, std::vector<Opcode> _ops)
:   mnem(_mnem),
    ops(_ops) {};

Insn& Insn::operator=(const Insn& insn) const {
    auto& a = std::move((const Insn)Insn(insn.mnem, insn.ops));
    return (Insn &)a;
}

bool Insn::operator==(const Insn& insn) const {
    if(ops.size() != insn.ops.size()) {
        return false;
    }
    for(int i=0; i<ops.size(); i++) {
        if(!std::visit(overloaded {
                    [](uint64_t a, RegType::Reg b) {return false;},
                    [](RegType::Reg a, uint64_t b) {return false;},
                    [](uint64_t a, uint64_t b) {return a == b;},
                    [](RegType::Reg a, RegType::Reg b) {return a == b;},
                    }, ops[i], insn.ops[i])) {
            return false;
        }
    }
    return mnem == insn.mnem;
}

std::optional<Opcode> Insn::strToOpcode(std::string s) {
    if (s.substr(0, 2) == "0x") {
        return std::stoul(s, 0, 16);
    }
    return RegType::fromString(s);
}

std::optional<Insn> Insn::fromString(const std::string& opcode) {
    //Ignore memory access like 'mov [rax], rbx'
    if(opcode.find('[') != std::string::npos) {
        return {};
    }
    //Ignore jmp/call instruction
    if(opcode.find('j') != std::string::npos
            || opcode.find("call") != std::string::npos) {
        return {};
    }
    char * const _mnem = new char[0x100];
    char *_ops = new char[0x100];
    char * const p = _ops;
    memset(_mnem, '\0', 0x100);
    memset(_ops, '\0', 0x100);
    if (_mnem == NULL || _ops == NULL) {
        std::cerr << "Allocation failed" << std::endl;
        delete[] _mnem;
        delete[] _ops;
        return {};
    }
    sscanf(opcode.c_str(), "%s %[^\n\t]", _mnem, _ops);
    Mnem mnem = _mnem;
    auto ops = std::vector<Opcode>();
    auto oplist = Util::split(_ops, ',');
    for(auto& op : oplist) {
        Util::trim(op, " ");
        auto o = strToOpcode(op);
        if(!o.has_value()) {
            std::cerr << "Unknown opcode: " << op << std::endl;
            return {};
        }
        ops.push_back(o.value());
    }
    delete[] _mnem;
    delete[] p;
    return Insn(mnem, ops);
}

std::optional<std::string> Insn::toString() const {
    //FIXME replace sprintf with safe function
    auto ret = new char[0x100];
    if(ret == NULL) {
        std::cerr << "Allocation failed" << std::endl;
        return {};
    }
    auto toStr = [](Opcode op){return std::visit(overloaded {
            [](uint64_t x){return std::to_string(x);},
            //FIXME return proper value when it fails
            [](RegType::Reg x){return RegType::toString(x).value();},
            }, op);};
    switch(ops.size()) {
    case 0:
        strcpy(ret, mnem.c_str());
        break;
    case 1:
        sprintf(ret, "%s %s", mnem.c_str(), toStr(ops[0]).c_str());
        break;
    case 2:
        sprintf(ret, "%s %s, %s", mnem.c_str(), toStr(ops[0]).c_str(),
                toStr(ops[1]).c_str());
        break;
    case 3:
        sprintf(ret, "%s %s, %s, %s", mnem.c_str(), toStr(ops[0]).c_str(),
                toStr(ops[1]).c_str(), toStr(ops[2]).c_str());
        break;
    }
    return std::string(ret);
}

bool Insn::operator!=(const Insn& insn) const {
    return !(*this == insn);
}
