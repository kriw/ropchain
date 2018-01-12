#include <iostream>
#include "regs.h"
#include "solver.h"
#include "arch.h"
#include "./frontend/r2/r2_loader.h"
#include "./frontend/rp++/rp_loader.h"

int main() {
    Arch::arch = Arch::AMD64;
    // auto gadgets = Frontend::R2::from("/bin/ls").value();
    auto gadgets = Frontend::RPP::from("/bin/ls").value();
    // auto gadgets = Frontend::RPP::from("/usr/lib/libc.so.6").value();
    auto rop = Solver::solveAvoidChars({{RegType::rdi, 0x41414141},
            {RegType::rsi, 0x42424242}}, gadgets, 0x2122232425262728, {});
    if(!rop.has_value()) {
        std::cerr << "Error" << std::endl;
    } else {
        rop.value().dump();
        std::cout << rop.value().payload() << std::endl;
    }
    return 0;
}
