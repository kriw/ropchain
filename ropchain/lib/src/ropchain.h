#pragma once
#include <vector>
#include <optional>
#include <iostream>
#include <variant>
#include "gadget.h"

typedef std::variant<Gadget, uint64_t> ROPElem;
typedef std::vector<ROPElem> ROPElems;
    
class ROPChain {
public:
    ROPChain();
    //move?
    ROPChain(const ROPElem elem);
    //move?
    ROPChain(const ROPElems elems);
    void append(const ROPElem elem);
    void dump() const;
    void setBaseAddr(const uint64_t addr);
    std::string payload() const;
    void chain(const ROPChain& ropchain);
    ROPElems getElems() const;
    size_t length() const;
    bool operator<(const ROPChain& rop) const;
    bool operator>(const ROPChain& rop) const {return rop < *this;};
    bool operator<=(const ROPChain& rop) const {return !(*this < rop);};
    bool operator>=(const ROPChain& rop) const {return !(rop > *this);};
private:
    uint64_t baseAddr;
    ROPElems elems;
};

typedef std::optional<ROPChain> OptROP;
