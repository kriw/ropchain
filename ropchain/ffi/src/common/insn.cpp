#include <utility>
#include "insn.h"
#include "util.h"

Insn::Insn(Mnem _mnem, std::vector<Operand> _ops)
:   hash(calcHash(_mnem, _ops)),
    mnem(std::move(_mnem)),
    ops(std::move(_ops))
{};

Insn& Insn::operator=(const Insn& insn) {
    if(this != &insn) {
        (std::string&)mnem = insn.mnem;
        (size_t&)hash = insn.hash;
        auto *_ops = (std::vector<Operand> *)&ops;
        _ops->clear();
        std::copy(insn.ops.begin(), insn.ops.end(),
                std::back_inserter(*_ops));
    }
    return *this;
}

bool Insn::operator==(const Insn& insn) const {
    if(hash != insn.hash) {
        return false;
    }
    if(ops.size() != insn.ops.size()) {
        return false;
    }
    const auto check = [](auto&& a, auto&& b) {
            using T = std::decay_t<decltype(a)>;
            using U = std::decay_t<decltype(b)>;
            if constexpr (!std::is_same_v<T, U>) {
                return false;
            }
            if constexpr (std::is_same_v<T, uint64_t>
                    && std::is_same_v<U, uint64_t>) {
                return a == b;
            }
            if constexpr (std::is_same_v<T, RegType::Reg>
                    && std::is_same_v<U, RegType::Reg>) {
                return a == b;
            }
            if constexpr (std::is_same_v<T, MemOp>
                    && std::is_same_v<U, MemOp>) {
                return a.first == b.first && a.second == b.second;
            }
            return false;
        };
    for(size_t i=0; i < ops.size(); i++) {
        if(!std::visit(check, ops[i], insn.ops[i])) {
            return false;
        }
    }
    return mnem == insn.mnem;
}

std::optional<RegOffset> regOffsetFromString(const std::string& _s) {
    //expect dword [reg] or [reg+offset] or [reg-offset] (TODO: [reg+reg])
    //XXX This is a dirty way
    if(_s.substr(0, 5) != "dword") {
        return {};
    }
    //XXX Same as above
    const auto s = _s.substr(6);
    if(s.front() != '[' || s.back() != ']') {
        return {};
    }
    const auto rr = s.substr(1, s.size() - 1);
    auto ss = Util::split(rr, "+-");
    if(2 < ss.size()) {
        ERR("unimplemented");
        return {};
    }
    //[reg]
    if(ss.size() == 1) {
        if(auto r = RegType::fromString(ss[0])) {
            return std::make_pair(r.value(), 0);
        }
    }
    //[reg(+or-)offset]
    if(ss.size() == 2) {
        if(auto r = RegType::fromString(ss[0])) {
            if(auto v = Util::toInt(ss[1])) {
                return std::make_pair(r.value(), v.value());
            }
        }
    }
    return {};
}

std::optional<Operand> Insn::strToOperand(const std::string& s) {
    if(auto v = Util::toInt(s)) {
        return v.value();
    }
    if(auto r = regOffsetFromString(s)) {
        return r;
    }
    return RegType::fromString(s);
}

std::optional<Insn> Insn::fromString(const std::string& opcode) {
    //Ignore memory access like 'mov [rax], rbx' except for "lea"
    if(opcode.find("lea") == std::string::npos
            && opcode.find('[') != std::string::npos) {
        return {};
    }
    //Ignore jmp/call instruction
    if(opcode.find('j') != std::string::npos
            || opcode.find("call") != std::string::npos) {
        return {};
    }
    char _mnem[101];
    char _ops[101];
    memset(_mnem, '\0', sizeof(_mnem));
    memset(_ops, '\0', sizeof(_ops));
    sscanf(opcode.c_str(), "%100s %100[^\n\t]", _mnem, _ops);
    Mnem mnem = _mnem;
    auto ops = std::vector<Operand>();
    auto oplist = Util::split(_ops, ",");
    for(auto& op : oplist) {
        Util::trim(op, " ");
        auto o = strToOperand(op);
        if(!o.has_value()) {
            ERR("Unknown opcode: ", op);
            return {};
        }
        ops.push_back(o.value());
    }
    return Insn(mnem, ops);
}

std::string Insn::toString() const {
    std::string ret = mnem.c_str();
    for(size_t i = 0; i < ops.size(); i++) {
        ret += ", " + opToStr(ops[i]);
    }
    return ret;
}

bool Insn::operator!=(const Insn& insn) const {
    return !(*this == insn);
}

std::optional<MemOp> Insn::memRef(const Operand& op, uint64_t offset) {
    if(auto r = std::get_if<RegType::Reg>(&op)) {
        return std::make_pair(*r, offset);
    }
    if(auto r = std::get_if<uint64_t>(&op)) {
        return *r;
    }
    return {};
}

size_t Insn::calcHash(const Mnem& mnem, const std::vector<Operand>& ops) {
    return (std::hash<std::string>{}(mnem) << 1) ^ std::hash<std::vector<Operand>>{}(ops);
}

std::string Insn::opToStr(const Operand& op) {
    return std::visit([](auto&& x) {
            using T = std::decay_t<decltype(x)>;
            if constexpr (std::is_same_v<T, uint64_t>) {
                return std::to_string(x);
            }
            if constexpr (std::is_same_v<T, RegType::Reg>) {
                auto retOpt = RegType::toString(x);
                if(retOpt.has_value()) {
                    return retOpt.value();
                }
            }
            //TODO MemOp
            if constexpr (std::is_same_v<T, MemOp>) {
                return std::string("TODO");
            }
            ERR("Failed to convert to String");
            return std::string();
        }, op);
}
