#include "arch.h"

size_t Arch::word() {
	if(_arch == X86) {
		return 4;
	}
	if(_arch == AMD64) {
		return 8;
	}
	return 0;
}

Arch::Arch Arch::arch() {
	return _arch;
}
