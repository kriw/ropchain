#include "../gadget.h"
#include <r_socket.h>

namespace Frontend {
    std::string test(const char *file);
    Gadgets fromCmd(R2Pipe *r2, const std::string& cmd);
    std::optional<Gadgets> fromR2(const std::string& fileName);
}
