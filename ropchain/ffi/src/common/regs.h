#pragma once
#include <optional>
#include <cstdint>
#include <bitset>
#include <map>

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
    static const std::map<Reg, Reg> x64RegMap = {
        {rax, rax}, {eax , rax}, {ax  , rax}, {ah, rax}, {al  , rax},
        {rbx, rbx}, {ebx , rbx}, {bx  , rbx}, {bh, rbx}, {bl  , rbx},
        {rcx, rcx}, {ecx , rcx}, {cx  , rcx}, {ch, rcx}, {cl  , rcx},
        {rdx, rdx}, {edx , rdx}, {dx  , rdx}, {dh, rdx}, {dl  , rdx},
        {rdi, rdi}, {edi , rdi}, {di  , rdi},            {dil , rdi},
        {rsi, rsi}, {esi , rsi}, {si  , rsi},            {sil , rsi},
        {rbp, rbp}, {ebp , rbp}, {bp  , rbp},            {bpl , rbp},
        {rsp, rsp}, {esp , rsp}, {sp  , rsp},            {spl , rsp},
        {r8,  r8}, {r8d , r8}, {r8w , r8},            {r8b , r8},
        {r9,  r9}, {r9d , r9}, {r9w , r9},            {r9b , r9},
        {r10, r10}, {r10d, r10}, {r10w, r10},            {r10b, r10},
        {r11, r11}, {r11d, r11}, {r11w, r11},            {r11b, r11},
        {r12, r12}, {r12d, r12}, {r12w, r12},            {r12b, r12},
        {r13, r13}, {r13d, r13}, {r13w, r13},            {r13b, r13},
        {r14, r14}, {r14d, r14}, {r14w, r14},            {r14b, r14},
        {r15, r15}, {r15d, r15}, {r15w, r15},            {r15b, r15}
    };
    static const std::map<Reg, Reg> x86RegMap = {
        {eax, eax }, {ax, eax}, {ah, eax}, {al , eax},
        {ebx, ebx }, {bx, ebx}, {bh, ebx}, {bl , ebx},
        {ecx, ecx }, {cx, ecx}, {ch, ecx}, {cl , ecx},
        {edx, edx }, {dx, edx}, {dh, edx}, {dl , edx},
        {edi, edi }, {di, edi},            {dil, edi},
        {esi, esi }, {si, esi},            {sil, esi},
        {ebp, ebp }, {bp, ebp},            {bpl, ebp},
        {esp, esp }, {sp, esp},            {spl, esp},
    };
    std::optional<std::string> toString(Reg r);
    std::optional<Reg> fromString(const std::string& s);
};

typedef std::bitset<80> RegSet;
