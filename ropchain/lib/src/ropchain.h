#pragma once
#include <vector>
#include "gadget.h"

class ROPChain {
public:
    ROPChain(Gadget gadget, uint64_t value, uint64_t base);
    void append(Gadget gadget, uint64_t value);
    void dump();
    void setBaseAddr(uint64_t addr);
    char *payload();
    void chain(const ROPChain& ropchain);
    size_t length();
private:
    uint64_t baseAddr;
    std::vector<Gadget> gadgets;
};
