#include "regs.h"

void RegSet::add(RegType::Reg r) {
    v |= r;
}
bool RegSet::exist(RegType::Reg r) {
    return v & r;
}
void RegSet::del(RegType::Reg r) {
    v &= ~r;
}
