#pragma once
#include <variant>
#include <cstdint>
#define TYPE(X) typedef struct X {} X;

//More registers (e.g. eax, ebx, al, ax, ...
namespace RegType {
    TYPE(rax); TYPE(eax);  TYPE(ax);  TYPE(ah); TYPE(al);
    TYPE(rbx); TYPE(ebx);  TYPE(bx);  TYPE(bh); TYPE(bl);
    TYPE(rcx); TYPE(ecx);  TYPE(cx);  TYPE(ch); TYPE(cl);
    TYPE(rdx); TYPE(edx);  TYPE(dx);  TYPE(dh); TYPE(dl);
    TYPE(rdi); TYPE(edi);  TYPE(di);            TYPE(dil);
    TYPE(rsi); TYPE(esi);  TYPE(si);            TYPE(sil);
    TYPE(rbp); TYPE(ebp);  TYPE(bp);            TYPE(bpl);
    TYPE(rsp); TYPE(esp);  TYPE(sp);            TYPE(spl);
    TYPE(r8);  TYPE(r8d);  TYPE(r8w);           TYPE(r8b);
    TYPE(r9);  TYPE(r9d);  TYPE(r9w);           TYPE(r9b);
    TYPE(r10); TYPE(r10d); TYPE(r10w);          TYPE(r10b);
    TYPE(r11); TYPE(r11d); TYPE(r11w);          TYPE(r11b);
    TYPE(r12); TYPE(r12d); TYPE(r12w);          TYPE(r12b);
    TYPE(r13); TYPE(r13d); TYPE(r13w);          TYPE(r13b);
    TYPE(r14); TYPE(r14d); TYPE(r14w);          TYPE(r14b);
    TYPE(r15); TYPE(r15d); TYPE(r15w);          TYPE(r15b);
    typedef std::variant<rax, eax, ax, ah, al,
            rbx, ebx, bx, bh, bl,
            rcx, ecx, cx, ch, cl,
            rdx, edx, dx, dh, dl,
            rdi, edi, dl, dil,
            rsi, esi, si, sil,
            rbp, ebp, bp, bpl,
            rsp, esp, sp, spl,
            r8, r8d, r8w, r8b,
            r9, r9d, r9w, r9b,
            r10, r10d, r10w, r10b,
            r11, r11d, r11w, r11b,
            r12, r12d, r12w, r12b,
            r13, r13d, r13w, r13b,
            r14, r14d, r14w, r14b,
            r15, r15d, r15w, r15b> Reg;
};

struct Reg {
    RegType::Reg type;
    uint64_t v;
};
