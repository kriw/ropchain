#include <iostream>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "../common/regs.h"
#include "../common/solver.h"
#include "../common/builder.h"
#include "../common/config.h"
#include "../common/frontend/r2/r2_loader.h"
#include "../common/frontend/rp++/rp_loader.h"

int c;
std::string filename = "";
uint64_t baseAddr = 0;
bool isDump = false;
std::map<RegType::Reg, uint64_t> dests;
std::set<char> avoids;
auto solver = Solver::solveWithFile;

void parseArgs(int argc, char **argv);

int main(int argc, char **argv) {
    parseArgs(argc, argv);
    auto rop = solver(dests, filename, baseAddr, {});
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

void printUsage() {
    std::cout <<
        "Usage:\n"
        "-a: Architecture, \"x86\" or \"amd64\"\n"
        "-b: Base address of binary file\n"
        "-d: Dump mode\n"
        "-f: Filename\n"
        "-g: ROPGadget loader, \"r2\" or \"rpp\"\n"
        "-i: Characters which should be excluded (e.g., -iabc\n"
        "--[reg]: Register value (e.g. --rax=0x1234 --rbx=11\n"
        "--fast: call function by fastcall\n"
        "--cdecl: call function by cdeclcall\n"
        << std::endl;
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
        {"r15", 1, NULL, 'N'},
        {"fastcall", 1, NULL, 'X'},
        {"cdecl", 1, NULL, 'Y'},
    };
    int ops_index;
    while(true) {
        int c = getopt_long(argc, argv, "a:b:df:g:hi:", ops, &ops_index);
        if(c == EOF) {
            break;
        }
        if(c == 'h') {
            printUsage();
            exit(0);
        }
    }
    optind = 0;
    while(true) {
        int c = getopt_long(argc, argv, "a:b:df:g:hi:", ops, &ops_index);
        if(c == EOF) {
            break;
        }
        if(c == 'a') {
            if(!strcmp("x86", optarg)) {
                Config::setArch(Config::Arch::X86);
            } else if(!strcmp("amd64", optarg)) {
                Config::setArch(Config::Arch::AMD64);
            } else {
                Config::setArch(Config::Arch::AMD64);
            }
        }
    }
    optind = 0;
    while((c = getopt_long(argc, argv, "a:b:df:g:hi:", ops, &ops_index)) != EOF) {
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
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::eax] = fromStr(optarg);
                } else {
                    dests[RegType::rax] = fromStr(optarg);
                }
                break;
            case 'B'://rbx/ebx
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::ebx] = fromStr(optarg);
                } else {
                    dests[RegType::rbx] = fromStr(optarg);
                }
                break;
            case 'C'://rcx/ecx
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::ecx] = fromStr(optarg);
                } else {
                    dests[RegType::rcx] = fromStr(optarg);
                }
                break;
            case 'D'://rdx/edx
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::edx] = fromStr(optarg);
                } else {
                    dests[RegType::rdx] = fromStr(optarg);
                }
                break;
            case 'E'://rdi/edi
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::edi] = fromStr(optarg);
                } else {
                    dests[RegType::rdi] = fromStr(optarg);
                }
                break;
            case 'F'://rsi/esi
                if(Config::getArch() == Config::Arch::X86) {
                    dests[RegType::esi] = fromStr(optarg);
                } else {
                    dests[RegType::rsi] = fromStr(optarg);
                }
                break;
            case 'G'://r8
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r8] = fromStr(optarg);
                }
                break;
            case 'H'://r9
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r9] = fromStr(optarg);
                }
                break;
            case 'I'://r10
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r10] = fromStr(optarg);
                }
                break;
            case 'J'://r11
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r11] = fromStr(optarg);
                }
                break;
            case 'K'://r12
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r12] = fromStr(optarg);
                }
                break;
            case 'L'://r13
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r13] = fromStr(optarg);
                }
                break;
            case 'M'://r14
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r14] = fromStr(optarg);
                }
                break;
            case 'N'://r15
                if(Config::getArch() == Config::Arch::AMD64) {
                    dests[RegType::r15] = fromStr(optarg);
                }
                break;
            case 'X':
                //fastcall
                //TODO args
                // const uint64_t funcAddr = fromStr(optarg);
                // solver = [&funcAddr](const std::map<RegType::Reg, uint64_t>& dests, const std::string& file,
                //         uint64_t base, const std::set<char>& avoids) {
                //     return Builder::fastCall(funcAddr, std::vector<uint64_t>(), dests, file, base, avoids);
                // };
                break;
            case 'Y':
                //cdecl
                //TODO args
                // const uint64_t funcAddr = fromStr(optarg);
                // solver = [&funcAddr](auto dests, auto file, auto base, auto avoids) {
                //     return Builder::cdeclCall(funcAddr, std::vector<uint64_t>(), dests, file, base, avoids);
                // };
                break;
        }
    }
    if(filename == "") {
        eprintf("Usage %s -f filename\n", argv[0]);
        exit(1);
    }
}
