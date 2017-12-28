#include <iostream>
#include "./frontend/r2_loader.h"

int main() {
    std::cout << Frontend::test("r2 -q0 /bin/ls") << std::endl;
    return 0;
}
