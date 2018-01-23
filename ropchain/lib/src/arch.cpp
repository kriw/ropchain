#include "arch.h"

size_t Arch::word() {
	if(arch == X86) {
		return 4;
	}
	if(arch == AMD64) {
		return 8;
	}
	return 0;
}

uint32_t Arch::bits() {
    return word() * 8;
}
