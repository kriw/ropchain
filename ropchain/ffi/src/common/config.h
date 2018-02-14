#pragma once
#include <cstddef>
#include <cstdint>
#include "frontend/r2/r2_loader.h"
#include "frontend/rp++/rp_loader.h"
#include "functional"

namespace Config {
    typedef std::function<std::optional<Gadgets>(const std::string&)> Loader;
    Loader getGadgetLoader();
    void setGadgetLoader(Loader loader);
    namespace _ {
        static Loader gadgetLoader;
    }

    namespace Arch {
        typedef int Arch;
        enum _enum_arch {
            X86, AMD64
        };
        size_t word();
        uint32_t bits();
        static Arch arch;
    };
    Arch::Arch getArch();
    void setArch(Arch::Arch _arch);
}
