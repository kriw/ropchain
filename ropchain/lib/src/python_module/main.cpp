#include <boost/python.hpp>
#include <boost/python/suite/indexing/map_indexing_suite.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
#include "../lib/ropchain.h"
#include "../lib/solver.h"
#include "../lib/frontend/r2/r2_loader.h"
#include "../lib/frontend/rp++/rp_loader.h"
#include "../lib/regs.h"

using namespace boost::python;

ROPChain solveWithFileWrapper(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::vector<char>& avoids) {
    std::set<char> _avoids(avoids.begin(), avoids.end());
    return Solver::solveWithFile(dests, file, base, _avoids).value();
}

BOOST_PYTHON_MODULE(ropchain) {
    def("solve", solveWithFileWrapper);
    class_<ROPChain>("ROPChain")
        .def("dump", &ROPChain::dump)
        .def("setBaseAddr", &ROPChain::dump)
        .def("payload", &ROPChain::payload)
        ;
    class_<std::map<RegType::Reg, uint64_t>>("RegValue")
        .def(map_indexing_suite<std::map<RegType::Reg, uint64_t>>());
    class_<std::vector<char>>("CharVec")
        .def(vector_indexing_suite<std::vector<char>>());
}
