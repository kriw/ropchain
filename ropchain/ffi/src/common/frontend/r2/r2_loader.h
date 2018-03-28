#include "../../gadget.h"
#ifdef _R2
#include <r_socket.h>
#endif

namespace Frontend {
    namespace R2 {
        std::optional<Gadgets> from(const std::string& fileName);
    }
}
