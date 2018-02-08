#include "../../gadget.h"
#include <r_socket.h>

namespace Frontend {
    namespace R2 {
        Gadgets fromCmd(R2Pipe *r2, const std::string& cmd);
        std::optional<Gadgets> from(const std::string& fileName);
    }
}
