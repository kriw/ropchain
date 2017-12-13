#pragma once
#include <vector>
#include <optional>
#include <iostream>
#include "gadget.h"

class ROPChain {
public:
    ROPChain(Gadget gadget, uint64_t value, uint64_t base);
    void append(Gadget gadget, uint64_t value);
    void dump() const;
    void setBaseAddr(uint64_t addr);
    std::string payload() const;
    void chain(const ROPChain& ropchain);
    Gadgets getGadgets() const;
    size_t length();
private:
    uint64_t baseAddr;
    std::vector<Gadget> gadgets;
};

typedef std::optional<ROPChain> OptROP;
namespace GadgetUtil {
    ROPChain toROP(const Gadget& gadget);
    OptROP toOptROP(const optGadget& gadget);
}
