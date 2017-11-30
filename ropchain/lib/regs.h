#include <variant>
#include <cstdint>

//More registers (e.g. eax, ebx, al, ax, ...
namespace RegType {
    typedef struct rax {} rax;
    typedef struct rbx {} rbx;
    typedef struct rcx {} rcx;
    typedef struct rdx {} rdx;
    typedef struct rdi {} rdi;
    typedef struct rsi {} rsi;
    typedef struct rbp {} rbp;
    typedef struct rsp {} rsp;
    typedef struct r8 {} r8;
    typedef struct r9 {} r9;
    typedef struct r10 {} r10;
    typedef struct r11 {} r11;
    typedef struct r12 {} r12;
    typedef struct r13 {} r13;
    typedef struct r14 {} r14;
    typedef struct r15 {} r15;
    typedef std::variant<rax, rbx, rcx, rdx, rdi, rsi,
            rbp, rsp, r8, r9, r10, r11, r12, r13, r14, r15> Reg;
};

struct Reg {
    RegType::Reg type;
    uint64_t v;
};
