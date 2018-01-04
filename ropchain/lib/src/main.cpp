#include <iostream>
#include "./frontend/r2_loader.h"

int main() {
    auto gadgets = Frontend::fromR2("/bin/ls").value();
    for(auto g : gadgets) {
        std::cout << g.toString() << std::endl;
    }
    return 0;
}
