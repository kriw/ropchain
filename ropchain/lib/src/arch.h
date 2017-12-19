#pragma once
#include <cstddef>

namespace Arch {
	typedef int Arch;
	enum _enum_arch {
		X86, AMD64
	};
	static Arch arch;
	size_t word();
};
