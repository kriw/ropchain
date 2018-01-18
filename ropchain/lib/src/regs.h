#pragma once
#include <optional>
#include <cstdint>
#include <bitset>

namespace RegType {
    enum Regs {
    none = 0,
    rax, eax, ax, ah, al, 
    rbx, ebx, bx, bh, bl, 
    rcx, ecx, cx, ch, cl, 
    rdx, edx, dx, dh, dl, 
    rdi, edi, di,   dil,
    rsi, esi, si,   sil,
    rbp, ebp, bp,   bpl,
    rsp, esp, sp,   spl,
    r8,  r8d, r8w,  r8b,
    r9,  r9d, r9w,  r9b,
    r10, r10d,r10w, r10b,
    r11, r11d,r11w, r11b,
    r12, r12d,r12w, r12b,
    r13, r13d,r13w, r13b,
    r14, r14d,r14w, r14b,
    r15, r15d,r15w, r15b
    };
    typedef int64_t Reg;
    std::optional<std::string> toString(Reg r);
    std::optional<Reg> fromString(const std::string s);
};

typedef std::bitset<80> RegSet;
