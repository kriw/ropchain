#pragma once
#include "frontend/r2/r2_loader.h"
#include "frontend/rp++/rp_loader.h"
#include "functional"

namespace Config {
    typedef std::function<std::optional<Gadgets>(const std::string&)> Loader;
    static Loader gadgetLoader = Frontend::RPP::from;
}
