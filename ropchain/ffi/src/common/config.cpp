#include "config.h"
#include "util.h"

Config::Loader Config::getGadgetLoader() {
    if (_::gadgetLoader == nullptr) {
#ifdef _R2
        return Frontend::R2::from;
#else
        return Frontend::RPP::from;
#endif
    }
    return _::gadgetLoader;
}

void Config::setGadgetLoader(Config::Loader loader) {
    _::gadgetLoader = loader;
}

namespace Config {
Arch::Arch getArch() { return Arch::arch; }

void setArch(Arch::Arch _arch) { Arch::arch = _arch; }

size_t Arch::word() {
    if (arch == X86) {
        return 4;
    }
    if (arch == AMD64) {
        return 8;
    }
    return 0;
}

uint32_t Arch::bits() { return word() * 8; }
} // namespace Config
