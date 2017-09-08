#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
char g_buf[10];

void fake() {
    read(0, g_buf, 10);
    system("");
}

void test(char *addr) {
    printf("%s\n", addr);
}

int main() {
    char buf[100];
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    scanf("%s", buf);
    return 0;
}
