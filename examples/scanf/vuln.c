#include <stdio.h>
#include <unistd.h>

int main() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    puts((char *)&stdout);
    char buf[0x100];
    scanf("%s", buf);
    return 0;
}
