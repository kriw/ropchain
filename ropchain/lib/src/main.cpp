#include <iostream>
#include "./frontend/r2/r2_loader.h"

int main() {
    auto gadgets = Frontend::R2::from("/bin/ls").value();
    for(auto g : gadgets) {
        std::cout << g.toString() << std::endl;
    }
    return 0;
}
