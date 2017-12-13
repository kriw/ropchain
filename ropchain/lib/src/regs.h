#pragma once
#include <variant>
#include <cstdint>
#define TYPE(X, v) const uint64_t X = (uint64_t)1 << v

//More registers (e.g. eax, ebx, al, ax, ...
namespace RegType {
    TYPE(rax, 0);  TYPE(eax, 1);   TYPE(ax, 2);    TYPE(al, 3);
    TYPE(rbx, 4);  TYPE(ebx, 5);   TYPE(bx, 6);    TYPE(bl, 7);
    TYPE(rcx, 8);  TYPE(ecx, 9);   TYPE(cx, 10);   TYPE(cl, 11);
    TYPE(rdx, 12); TYPE(edx, 13);  TYPE(dx, 14);   TYPE(dl, 15);
    TYPE(rdi, 16); TYPE(edi, 17);  TYPE(di, 18);   TYPE(dil, 19);
    TYPE(rsi, 20); TYPE(esi, 21);  TYPE(si, 22);   TYPE(sil, 23);
    TYPE(rbp, 24); TYPE(ebp, 25);  TYPE(bp, 26);   TYPE(bpl, 27);
    TYPE(rsp, 28); TYPE(esp, 29);  TYPE(sp, 30);   TYPE(spl, 31);
    TYPE(r8, 32);  TYPE(r8d, 33);  TYPE(r8w, 34);  TYPE(r8b, 35);
    TYPE(r9, 36);  TYPE(r9d, 37);  TYPE(r9w, 38);  TYPE(r9b, 39);
    TYPE(r10, 40); TYPE(r10d, 41); TYPE(r10w, 42); TYPE(r10b, 43);
    TYPE(r11, 44); TYPE(r11d, 45); TYPE(r11w, 46); TYPE(r11b, 47);
    TYPE(r12, 48); TYPE(r12d, 49); TYPE(r12w, 50); TYPE(r12b, 51);
    TYPE(r13, 52); TYPE(r13d, 53); TYPE(r13w, 54); TYPE(r13b, 55);
    TYPE(r14, 56); TYPE(r14d, 57); TYPE(r14w, 58); TYPE(r14b, 59);
    TYPE(r15, 60); TYPE(r15d, 61); TYPE(r15w, 62); TYPE(r15b, 63);
    typedef uint64_t Reg;

};

class RegSet {
public:
    RegSet();
    RegSet(uint64_t v);
    void add(RegType::Reg r);
    void del(RegType::Reg r);
    bool exist(RegType::Reg r) const;
    uint64_t val() const;
    RegSet operator&(const RegSet& rs) const;
    bool operator==(const RegSet& rs) const;
    bool operator<(const RegSet& rs) const;
    bool operator>(const RegSet& rs) const;
    bool operator<=(const RegSet& rs) const;
    bool operator>=(const RegSet& rs) const;
private:
    uint64_t v;
};

struct Reg {
    RegType::Reg type;
    uint64_t v;
};
