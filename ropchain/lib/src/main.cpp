#include <iostream>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "lib/regs.h"
#include "lib/solver.h"
#include "lib/arch.h"
#include "lib/config.h"
#include "lib/frontend/r2/r2_loader.h"
#include "lib/frontend/rp++/rp_loader.h"

int c;
std::string filename = "";
uint64_t baseAddr = 0;
bool isDump = false;
std::map<RegType::Reg, uint64_t> dests;
std::set<char> avoids;

void parseArgs(int argc, char **argv);

int main(int argc, char **argv) {
    parseArgs(argc, argv);
    auto rop = Solver::solveWithFile(dests, filename, baseAddr, {});
    if(!rop.has_value()) {
        std::cerr << "Error" << std::endl;
        exit(1);
    }
    if(isDump) {
        rop.value().dump();
    } else {
        std::cout << rop.value().payload() << std::endl;
    }
    return 0;
}

uint64_t fromStr(char *s) {
    int base = 10;
    if(!strncmp(s, "0x", 2)) {
        base = 16;
    }
    //TODO catch exception
    return std::stoul(s, nullptr, base);
}

void parseArgs(int argc, char **argv) {
    static struct option ops[] = {
        {"rax", 1, NULL, 'A'},
        {"eax", 1, NULL, 'A'},
        {"rbx", 1, NULL, 'B'},
        {"ebx", 1, NULL, 'B'},
        {"rcx", 1, NULL, 'C'},
        {"ecx", 1, NULL, 'C'},
        {"rdx", 1, NULL, 'D'},
        {"edx", 1, NULL, 'D'},
        {"rdi", 1, NULL, 'E'},
        {"edi", 1, NULL, 'E'},
        {"rsi", 1, NULL, 'F'},
        {"esi", 1, NULL, 'F'},
        {"r8", 1, NULL, 'G'},
        {"r9", 1, NULL, 'H'},
        {"r10", 1, NULL, 'I'},
        {"r11", 1, NULL, 'J'},
        {"r12", 1, NULL, 'K'},
        {"r13", 1, NULL, 'L'},
        {"r14", 1, NULL, 'M'},
        {"r15", 1, NULL, 'N'}
    };
    int ops_index;
    while(true) {
        int c = getopt_long(argc, argv, "a:b:df:g:i:", ops, &ops_index);
        if(c == EOF) {
            break;
        }
        if(c == 'a') {
            if(!strcmp("x86", optarg)) {
                Arch::arch = Arch::AMD64;
            } else if(!strcmp("amd64", optarg)) {
                Arch::arch = Arch::X86;
            } else {
                Arch::arch = Arch::AMD64;
            }
        }
    }
    optind = 0;
    while((c = getopt_long(argc, argv, "b:df:g:i:", ops, &ops_index)) != EOF) {
        switch(c) {
            case 'b':
                baseAddr = fromStr(optarg);
                break;
            case 'd':
                isDump = true;
                break;
            case 'f':
                filename = std::string(optarg);
                break;
            case 'g':
                if(!strcmp("r2", optarg)) {
                    Config::setGadgetLoader(Frontend::R2::from);
                } else if(!strcmp("rpp", optarg)) {
                    Config::setGadgetLoader(Frontend::RPP::from);
                }
                break;
            case 'i':
                for(int i = 0; optarg[i]; i++) {
                    avoids.insert(optarg[i]);
                }
                break;
            case 'A'://rax/eax
                if(Arch::arch == Arch::X86) {
                    dests[RegType::eax] = fromStr(optarg);
                } else {
                    dests[RegType::rax] = fromStr(optarg);
                }
                break;
            case 'B'://rbx/ebx
                if(Arch::arch == Arch::X86) {
                    dests[RegType::ebx] = fromStr(optarg);
                } else {
                    dests[RegType::rbx] = fromStr(optarg);
                }
                break;
            case 'C'://rcx/ecx
                if(Arch::arch == Arch::X86) {
                    dests[RegType::ecx] = fromStr(optarg);
                } else {
                    dests[RegType::rcx] = fromStr(optarg);
                }
                break;
            case 'D'://rdx/edx
                if(Arch::arch == Arch::X86) {
                    dests[RegType::edx] = fromStr(optarg);
                } else {
                    dests[RegType::rdx] = fromStr(optarg);
                }
                break;
            case 'E'://rdi/edi
                if(Arch::arch == Arch::X86) {
                    dests[RegType::edi] = fromStr(optarg);
                } else {
                    dests[RegType::rdi] = fromStr(optarg);
                }
                break;
            case 'F'://rsi/esi
                if(Arch::arch == Arch::X86) {
                    dests[RegType::esi] = fromStr(optarg);
                } else {
                    dests[RegType::rsi] = fromStr(optarg);
                }
                break;
            case 'G'://r8
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r8] = fromStr(optarg);
                }
                break;
            case 'H'://r9
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r9] = fromStr(optarg);
                }
                break;
            case 'I'://r10
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r10] = fromStr(optarg);
                }
                break;
            case 'J'://r11
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r11] = fromStr(optarg);
                }
                break;
            case 'K'://r12
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r12] = fromStr(optarg);
                }
                break;
            case 'L'://r13
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r13] = fromStr(optarg);
                }
                break;
            case 'M'://r14
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r14] = fromStr(optarg);
                }
                break;
            case 'N'://r15
                if(Arch::arch == Arch::AMD64) {
                    dests[RegType::r15] = fromStr(optarg);
                }
                break;
        }
    }
    if(filename == "") {
        eprintf("Usage %s -f filename\n", argv[0]);
        exit(1);
    }
}
