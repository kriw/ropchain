#include <iostream>
#include "./frontend/r2/r2_loader.h"
#include "./frontend/rp++/rp_loader.h"

int main() {
    // auto gadgets = Frontend::R2::from("/bin/ls").value();
    auto gadgets = Frontend::RPP::from("/bin/ls").value();
    std::cout << gadgets.size() << std::endl;
    for(auto g : gadgets) {
        std::cout << g.toString() << std::endl;
    }
    return 0;
}
