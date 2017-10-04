#include <stdio.h>
#include <unistd.h>

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    puts((char *)&stdout);
    char buf[0x100];
    read(0, buf, 0x1000);
    return 0;
}
