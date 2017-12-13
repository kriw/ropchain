#include "regs.h"

RegSet::RegSet() {
    v = 0;
}
RegSet::RegSet(uint64_t _v) {
    v = _v;
}
void RegSet::add(RegType::Reg r) {
    v |= r;
}
bool RegSet::exist(RegType::Reg r) const {
    return v & r;
}
void RegSet::del(RegType::Reg r) {
    v &= ~r;
}
uint64_t RegSet::val() const {
    return v;
}
RegSet RegSet::operator&(const RegSet& rs) const {
    return RegSet(v & rs.val());
}
bool RegSet::operator==(const RegSet& rs) const {
    return v == rs.val();
}
bool RegSet::operator<(const RegSet& rs) const {
    return v & rs.val() == rs.val();
}
bool RegSet::operator>(const RegSet& rs) const {
    return rs < *this;
}
bool RegSet::operator<=(const RegSet& rs) const {
    return !(*this < rs);
}
bool RegSet::operator>=(const RegSet& rs) const {
    return !(rs < *this);
}
