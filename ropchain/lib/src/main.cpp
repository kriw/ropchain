#include <iostream>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "regs.h"
#include "solver.h"
#include "arch.h"
#include "./frontend/r2/r2_loader.h"
#include "./frontend/rp++/rp_loader.h"

int c;
std::string filename = "";
bool isDump = false;
auto gadgetLoader = Frontend::R2::from;

void parseArgs(int argc, char **argv);

int main(int argc, char **argv) {
    parseArgs(argc, argv);
    auto gadgets = gadgetLoader(filename).value();
    auto rop = Solver::solveAvoidChars({{RegType::rdi, 0x41414141},
            {RegType::rsi, 0x42424242}}, gadgets, 0x2122232425262728, {});
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

void parseArgs(int argc, char **argv) {
    static struct option ops[] = {
        {"rax", 1, NULL, 'A'},
        {"rbx", 1, NULL, 'B'},
        {"rcx", 1, NULL, 'C'},
        {"rdx", 1, NULL, 'D'},
        {"rdi", 1, NULL, 'E'},
        {"rsi", 1, NULL, 'F'},
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
    while((c = getopt_long(argc, argv, "a:b:df:", ops, &ops_index)) != EOF) {
        switch(c) {
            case 'a':
                if(!strcmp("x86", optarg)) {
                    Arch::arch = Arch::AMD64;
                } else if(!strcmp("amd64", optarg)) {
                    Arch::arch = Arch::X86;
                } else {
                    Arch::arch = Arch::AMD64;
                }
                break;
            case 'b':
                if(!strcmp("r2", optarg)) {
                    gadgetLoader = Frontend::R2::from;
                } else if(!strcmp("rpp", optarg)) {
                    gadgetLoader = Frontend::RPP::from;
                }
                break;
            case 'd':
                isDump = true;
                break;
            case 'f':
                filename = std::string(optarg);
                break;
            case 'A'://rax
                //TODO
                break;
            case 'B'://rbx
                //TODO
                break;
            case 'C'://rcx
                //TODO
                break;
            case 'D'://rdx
                //TODO
                break;
            case 'E'://rdi
                //TODO
                break;
            case 'F'://rsi
                //TODO
                break;
            case 'G'://r8
                //TODO
                break;
            case 'H'://r9
                //TODO
                break;
            case 'I'://r10
                //TODO
                break;
            case 'J'://r11
                //TODO
                break;
            case 'K'://r12
                //TODO
                break;
            case 'L'://r13
                //TODO
                break;
            case 'M'://r14
                //TODO
                break;
            case 'N'://r15
                //TODO
                break;
        }
    }
    if(filename == "") {
        eprintf("Usage %s -f filename\n", argv[0]);
        exit(1);
    }
}
