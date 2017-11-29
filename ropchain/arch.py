
X86 = 'x86'
AMD64 = 'amd64'
arch = X86
def word():
    if arch == X86:
        return 4
    elif arch == AMD64:
        return 8
    else:
        return 0

def bits():
    if arch == X86:
        return 32
    elif arch == AMD64:
        return 64
    else:
        return 0
