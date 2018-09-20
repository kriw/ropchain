#include <r_core.h>
#include <r_lib.h>
#include <iostream>
#include "../common/builder.h"
#include "../common/config.h"
#include "../common/regs.h"
#include "../common/solver.h"

#undef R_API
#define R_API static
#undef R_IPI
#define R_IPI static

void cmd_search(RCore *core, const char *input) {
    // TODO
}

void usage() {
    puts("/Rc");
    puts("/Rcr <reg>=<value>");
    puts("/Rcl");
    puts("/Rcb");
}

int cmd(void *user, const char *input) {
    if (strncmp("/Rc", input, 2)) {
        return false;
    }
    cmd_search((RCore *)user, input);
    return true;
}

int init(void *user, const char *_input) { return true; }

RCorePlugin r_core_plugin_test = {
    "ropchain",                   // name
    "r2 interface for ropchain",  // desc
    "GPL-3.0",                    // license
    "kriw",                       // author
    "0.1-dev",                    // version
    cmd,                          // call
    init                          // init
};

#ifndef CORELIB
RLibStruct radare_plugin = {
    R_LIB_TYPE_CORE,      // type
    &r_core_plugin_test,  // data
    R2_VERSION            // version
};
#endif
