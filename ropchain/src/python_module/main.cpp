#include <boost/python.hpp>
#include <boost/python/suite/indexing/map_indexing_suite.hpp>
#include <boost/python/suite/indexing/vector_indexing_suite.hpp>
#include "../common/ropchain.h"
#include "../common/solver.h"
#include "../common/frontend/r2/r2_loader.h"
#include "../common/frontend/rp++/rp_loader.h"
#include "../common/regs.h"
#include "../common/config.h"

using namespace boost::python;

ROPChain solveWithFileWrapper(const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
        uint64_t base, const std::vector<char>& avoids) {
    std::set<char> _avoids(avoids.begin(), avoids.end());
    Config::setGadgetLoader(Frontend::RPP::from);
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
    enum_<RegType::Regs>("Regs")
        .value("none", RegType::none)
        .value("rax", RegType::rax)
        .value("eax", RegType::eax)
        .value("rbx", RegType::rbx)
        .value("ebx", RegType::ebx)
        .value("rcx", RegType::rcx)
        .value("ecx", RegType::ecx)
        .value("rdx", RegType::rdx)
        .value("edx", RegType::edx)
        .value("rdi", RegType::rdi)
        .value("edi", RegType::edi)
        .value("rsi", RegType::rsi)
        .value("esi", RegType::esi)
        .value("rbp", RegType::rbp)
        .value("ebp", RegType::ebp)
        .value("rsp", RegType::rsp)
        .value("esp", RegType::esp)
        .value("r8", RegType::r8)
        .value("r9", RegType::r9)
        .value("r10", RegType::r10)
        .value("r11", RegType::r11)
        .value("r12", RegType::r12)
        .value("r13", RegType::r13)
        .value("r14", RegType::r14)
        .value("r15", RegType::r15)
        ;
}
