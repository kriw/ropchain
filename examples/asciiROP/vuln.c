#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
int is_ascii(char c){
    if (c <= 0x1f || c >= 0x7f) return 0; // 0x20 == ' ' 
    return 1;
}

int main(){
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);

    char buf[0x10];
    void *MEM = (void *)0x55550000;
    const unsigned int MEMSIZE = 0x1c0000;
    char *mem = mmap(MEM, MEMSIZE,
                   PROT_READ   | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_FIXED  | MAP_ANONYMOUS,
                   -1, 0
            );
    if(mem != MEM){
        puts("mmap failed");
        exit(1);
    }
    FILE *fp = fopen("./libc.so.6", "r");
    if(fp == NULL) {
        puts("open ./libc.so.6 failed");
        exit(1);
    }
    fread(mem, MEMSIZE, 1, fp);
    fclose(fp);

    mprotect(mem, MEMSIZE, PROT_READ | PROT_EXEC);


    const int BUFSIZE = 0xffff;
    int i;
    char *heap = (char *)malloc(BUFSIZE);
    memset(heap, '\0', BUFSIZE);
    read(0, heap, BUFSIZE);
    for(i=0; i<BUFSIZE; i++) {
        if(!is_ascii(heap[i])) {
            memset(heap+i, '\0', BUFSIZE-i);
            break;
        }
    }
    strncpy(buf, heap, i);
    return 0;
}
