#include <boost/python.hpp>
#include "../lib/ropchain.h"
#include "../lib/solver.h"
#include "../lib/frontend/r2/r2_loader.h"
#include "../lib/frontend/rp++/rp_loader.h"
#include "../lib/regs.h"

using namespace boost::python;

BOOST_PYTHON_MODULE(ropchain) {
    def("solve", Solver::solveAvoidChars);
    // class_<ROPChain>("ROPChain")
    //     .def("dump", &ROPChain::dump)
    //     .def("setBaseAddr", &ROPChain::dump)
    //     .def("payload", &ROPChain::payload)
    //     ;
}
