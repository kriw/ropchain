#pragma once
#include <cstddef>
#include <cstdint>

namespace Arch {
	typedef int Arch;
	enum _enum_arch {
		X86, AMD64
	};
	static Arch arch = AMD64;
	size_t word();
    uint32_t bits();
};
