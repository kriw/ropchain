#include <sstream>
#include <iostream>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <array>
#include <string>
#include "rp_loader.h"
#include "../../util.h"

//FIXME
const std::string scriptPath = "./src/lib/frontend/rp++/rp_script.sh";

std::optional<std::string> _exec(const std::string& cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::shared_ptr<FILE> pipe(popen(cmd.c_str(), "r"), pclose);
    if (!pipe) return {};
    while (!feof(pipe.get())) {
        if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
            result += buffer.data();
    }
    return result;
}
std::optional<Gadgets> Frontend::RPP::from(const std::string& fileName) {
    std::cout << "filename: " << fileName << std::endl;
    std::optional<std::string> gadgetsStr = _exec(scriptPath + " " + fileName);
    if(!gadgetsStr.has_value()) {
        return {};
    }
    std::stringstream ss(gadgetsStr.value());
    std::string s;
    Gadgets gadgets;
    while(getline(ss, s)) {
        size_t sz = 2;
        const uint64_t addr = stoull(s.substr(0, s.find(':')), &sz, 16);
        s = s.substr(s.find(' '));
        if(auto g = Util::parseGadgetString(addr, s)) {
            gadgets.push_back(g.value());
        }
    }
    return gadgets;
}
