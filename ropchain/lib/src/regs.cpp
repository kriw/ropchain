#include "regs.h"

#define TOSTR(x) case x: return "x";

std::string RegType::toString(RegType::Reg r) {
	switch(r) {
TOSTR(rax) TOSTR(eax) TOSTR(ax) TOSTR(ah) TOSTR(al)
TOSTR(rbx) TOSTR(ebx) TOSTR(bx) TOSTR(bh) TOSTR(bl)
TOSTR(rcx) TOSTR(ecx) TOSTR(cx) TOSTR(ch) TOSTR(cl)
TOSTR(rdx) TOSTR(edx) TOSTR(dx) TOSTR(dh) TOSTR(dl)
TOSTR(rdi) TOSTR(edi) TOSTR(di) TOSTR(dil)
TOSTR(rsi) TOSTR(esi) TOSTR(si) TOSTR(sil)
TOSTR(rbp) TOSTR(ebp) TOSTR(bp) TOSTR(bpl)
TOSTR(rsp) TOSTR(esp) TOSTR(sp) TOSTR(spl)
TOSTR(r8) TOSTR(r8d) TOSTR(r8w) TOSTR(r8b)
TOSTR(r9) TOSTR(r9d) TOSTR(r9w) TOSTR(r9b)
TOSTR(r10) TOSTR(r10d) TOSTR(r10w) TOSTR(r10b)
TOSTR(r11) TOSTR(r11d) TOSTR(r11w) TOSTR(r11b)
TOSTR(r12) TOSTR(r12d) TOSTR(r12w) TOSTR(r12b)
TOSTR(r13) TOSTR(r13d) TOSTR(r13w) TOSTR(r13b)
TOSTR(r14) TOSTR(r14d) TOSTR(r14w) TOSTR(r14b)
TOSTR(r15) TOSTR(r15d) TOSTR(r15w) TOSTR(r15b)
	default:
		return "none";
	}
}
