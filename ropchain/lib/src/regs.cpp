#include "regs.h"
#include <iostream>

#define TOSTR(x) case x: return #x;
#define EQSTR(s, x) if (s == #x) return x;

std::optional<std::string> RegType::toString(RegType::Reg r) {
	switch(r) {
TOSTR(rax) TOSTR(eax)  TOSTR(ax)   TOSTR(ah) TOSTR(al)
TOSTR(rbx) TOSTR(ebx)  TOSTR(bx)   TOSTR(bh) TOSTR(bl)
TOSTR(rcx) TOSTR(ecx)  TOSTR(cx)   TOSTR(ch) TOSTR(cl)
TOSTR(rdx) TOSTR(edx)  TOSTR(dx)   TOSTR(dh) TOSTR(dl)
TOSTR(rdi) TOSTR(edi)  TOSTR(di)             TOSTR(dil)
TOSTR(rsi) TOSTR(esi)  TOSTR(si)             TOSTR(sil)
TOSTR(rbp) TOSTR(ebp)  TOSTR(bp)             TOSTR(bpl)
TOSTR(rsp) TOSTR(esp)  TOSTR(sp)             TOSTR(spl)
TOSTR(r8)  TOSTR(r8d)  TOSTR(r8w)            TOSTR(r8b)
TOSTR(r9)  TOSTR(r9d)  TOSTR(r9w)            TOSTR(r9b)
TOSTR(r10) TOSTR(r10d) TOSTR(r10w)           TOSTR(r10b)
TOSTR(r11) TOSTR(r11d) TOSTR(r11w)           TOSTR(r11b)
TOSTR(r12) TOSTR(r12d) TOSTR(r12w)           TOSTR(r12b)
TOSTR(r13) TOSTR(r13d) TOSTR(r13w)           TOSTR(r13b)
TOSTR(r14) TOSTR(r14d) TOSTR(r14w)           TOSTR(r14b)
TOSTR(r15) TOSTR(r15d) TOSTR(r15w)           TOSTR(r15b)
	default:
		return {};
	}
}

std::optional<RegType::Reg> RegType::fromString(const std::string& s) {
EQSTR(s, rax) EQSTR(s, eax)  EQSTR(s, ax)   EQSTR(s, ah) EQSTR(s, al)
EQSTR(s, rbx) EQSTR(s, ebx)  EQSTR(s, bx)   EQSTR(s, bh) EQSTR(s, bl)
EQSTR(s, rcx) EQSTR(s, ecx)  EQSTR(s, cx)   EQSTR(s, ch) EQSTR(s, cl)
EQSTR(s, rdx) EQSTR(s, edx)  EQSTR(s, dx)   EQSTR(s, dh) EQSTR(s, dl)
EQSTR(s, rdi) EQSTR(s, edi)  EQSTR(s, di)                EQSTR(s, dil)
EQSTR(s, rsi) EQSTR(s, esi)  EQSTR(s, si)                EQSTR(s, sil)
EQSTR(s, rbp) EQSTR(s, ebp)  EQSTR(s, bp)                EQSTR(s, bpl)
EQSTR(s, rsp) EQSTR(s, esp)  EQSTR(s, sp)                EQSTR(s, spl)
EQSTR(s, r8)  EQSTR(s, r8d)  EQSTR(s, r8w)               EQSTR(s, r8b)
EQSTR(s, r9)  EQSTR(s, r9d)  EQSTR(s, r9w)               EQSTR(s, r9b)
EQSTR(s, r10) EQSTR(s, r10d) EQSTR(s, r10w)              EQSTR(s, r10b)
EQSTR(s, r11) EQSTR(s, r11d) EQSTR(s, r11w)              EQSTR(s, r11b)
EQSTR(s, r12) EQSTR(s, r12d) EQSTR(s, r12w)              EQSTR(s, r12b)
EQSTR(s, r13) EQSTR(s, r13d) EQSTR(s, r13w)              EQSTR(s, r13b)
EQSTR(s, r14) EQSTR(s, r14d) EQSTR(s, r14w)              EQSTR(s, r14b)
EQSTR(s, r15) EQSTR(s, r15d) EQSTR(s, r15w)              EQSTR(s, r15b)
    return {};
}
