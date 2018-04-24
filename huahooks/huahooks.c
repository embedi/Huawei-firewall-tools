#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <unistd.h>
#include "headers.h"
#include <sys/mman.h>
#include <stdarg.h>
#include <pthread.h>
#include <asm/cachectl.h>
#include <errno.h>
#include <string.h>

extern char *__progname;

#define NUMBER_OF_HOOKS 10
#define SPLICE_SIZE 7*4
#define INVALID_MOD_BASE 0x1337


void fPrintToFile(const char *fmt, ...) {
    char buffer[4096];
    memset(buffer, 0, 4096);
    va_list args;
    va_start(args, fmt);
    int rc = vsnprintf(buffer, sizeof(buffer), fmt, args);
    va_end(args);

    FILE* f;
    f = fopen("/fpath.log", "a");
    fwrite(buffer, strlen(buffer), 1, f);
    fclose(f);
}

void fGetModBaseByName(char *cModName, ModuleRange* pModRange) {
    // read /proc/$pid/maps -_-
    char  cProcStr[256] = {0};
    char  cLine[256] = {0};
    size_t len;
    ssize_t read;
    unsigned char* pStart = INVALID_MOD_BASE;
    unsigned char* pEnd = INVALID_MOD_BASE;

    sprintf(cProcStr, "/proc/%i/maps", getpid());

    FILE* fp = fopen(cProcStr, "r");
    if (!fp) {
        fPrintToFile("\tFailed to open \"%s\"\n", cProcStr);
        perror("\t");
    }
    while ( fgets(cLine, 255, fp) != 0) {
        if (strstr(cLine, cModName) != 0) {
            char* pMinus = strstr(cLine, "-");
            *pMinus = '\x00';
            pStart = strtol(cLine, 0, 16);
            *(pMinus+9+2) = '\x00';
            pEnd = strtol(pMinus+1, 0, 16);
            break;
        }
    }

    pModRange->pStart = pStart;
    pModRange->pEnd = pEnd;
}



__attribute__((constructor)) int fInit() {
    pthread_mutex_init(&lock, NULL);

    stdout = stderr;
    memset(lHookEntries, 0, NUMBER_OF_HOOKS * sizeof(HOOK_ENTRY));

    void* std = dlopen("libc.so.6", RTLD_LAZY);
    if (!std) {
        fPrintToFile("\tNo libc.so.6\n");
        return -1;
    }

    // set up hooks here like that:
    //
    // unsigned char sPattern[] = {0x67,0xBD,0xFF,0x70,0xFF,0xBC,0x00,0x78,0x3C,0x1C,0x00,0x03,0xFF,0xB5,0x00,0x60,0x03,0x99,0xE0,0x2D,0xFF,0xB2,0x00,0x48,0x67,0x9C,0x84,0x88,0xFF,0xBF,0x00,0x88,0x00,0xA0,0xA8,0x2D,0xFF,0xBE,0x00,0x80,0x00,0xA0,0x90,0x2D,0xFF,0xB7,0x00,0x70,0xFF,0xB6,0x00,0x68,0xFF,0xB4,0x00,0x58};
    // strcpy(lHookEntries[0].sProgName, "fpath.out");
    // strcpy(lHookEntries[0].sModName, "/lib64/libpthread-2.11.1.so");
    // memcpy(lHookEntries[0].sPattern, sPattern, sizeof(sPattern));
    // lHookEntries[0].iPatternLen = sizeof(sPattern);
    // lHookEntries[0].pfnCallback = fHookPthreadCreate;


    ModuleRange ModRange;
    fGetModBaseByName(lHookEntries[0].sModName, &ModRange);
    fPrintToFile("fInit | fGetModBaseByName | %p %p\n", ModRange.pStart, ModRange.pEnd);
    if (ModRange.pStart != INVALID_MOD_BASE) {
        fSetHooks(__progname, lHookEntries[0].sModName, &ModRange);
    }
    return 0;
}

void fInstallHook(int iHookId) {
    HOOK_ENTRY* oHook = &lHookEntries[iHookId];
    memcpy(oHook->pResolvedAddr, oHook->sHook, SPLICE_SIZE);
    cacheflush(oHook->pResolvedAddr, SPLICE_SIZE, BCACHE);
    return;
}

void fRestoreProlog(int iHookId) {
    HOOK_ENTRY* oHook = &lHookEntries[iHookId];
    memcpy(oHook->pResolvedAddr, oHook->sProlog, SPLICE_SIZE);
    cacheflush(oHook->pResolvedAddr, SPLICE_SIZE, BCACHE);
    return;
}


// at the moment doesn't jump to original function
void fSetHook(HOOK_ENTRY* oHook) {
    // addresses are of 40 bits

    fPrintToFile("\tfSetHook called: pEntry at %p | pfnCallback at %p\n",
            oHook->pResolvedAddr, oHook->pfnCallback);

    size_t pagesize = sysconf(_SC_PAGESIZE);
    if (mprotect((uintptr_t)oHook->pResolvedAddr & -pagesize, pagesize, PROT_READ | PROT_WRITE | PROT_EXEC)) {
        perror("\tmprotect failed\n");
        return;
    }

    UINT32 cSplice[SPLICE_SIZE];

    fPrintToFile("\tHigher part = 0x%x\n", (unsigned int)((UINT64)oHook->pfnCallback >> 24));
    fPrintToFile("\tMiddle part = 0x%x\n", (unsigned int)(((UINT64)oHook->pfnCallback >> 8) & 0xFFFF));

    // move $at, $zero
    cSplice[0] = 0x200824;
    // lui $at A(40:24)
    cSplice[1] = 0x3C010000 + (unsigned int)((UINT64)oHook->pfnCallback >> 24);
    // ori $at, A(24:8)
    cSplice[2] = 0x34210000 + (unsigned int)(((UINT64)oHook->pfnCallback >> 8) & 0xFFFF);
    // dsll $at, 8
    cSplice[3] = 0x10A38;
    // ori  $at, A(8:0)
    cSplice[4] = 0x34210000 + (unsigned int)((UINT64)oHook->pfnCallback & 0xFF);
    // jr $at
    cSplice[5] = 0x200008;
    // move $t9, $at - used in gp calculations
    cSplice[6] = 0x20C825;

    if (memcmp(oHook->pResolvedAddr, cSplice, SPLICE_SIZE) == 0) {
        fPrintToFile("\tfSetHook tried to hook already hooked function!!!\n");
        return;
    }

    memcpy(oHook->sHook, cSplice, SPLICE_SIZE);
    memcpy(oHook->sProlog, oHook->pResolvedAddr, SPLICE_SIZE);
    memcpy(oHook->pResolvedAddr, oHook->sHook, SPLICE_SIZE);

    return;
}


void fSetHooks(char* sProgName, char* sModName, ModuleRange* pModRange) {
    fPrintToFile("\tfSetHooks called: sProgName = \"%s\" sModName = \"%s\"\n\t\tpStart = %p\tpEnd = %p\n", sProgName, sModName, pModRange->pStart, pModRange->pEnd);
    if (pModRange->pStart == INVALID_MOD_BASE)
        return;        
    for (HOOK_ENTRY* heTemp = lHookEntries; heTemp->iPatternLen != 0; heTemp++) {
        if ( strcmp(sProgName, heTemp->sProgName) == 0 &&
                strcmp(sModName, heTemp->sModName) == 0 ) {

            unsigned char* p = pModRange->pStart;

            while (p < pModRange->pEnd) {
                int bMatch = 1;
                if (*p == heTemp->sPattern[0]) {
                    for (unsigned char* i = p; i < p + heTemp->iPatternLen; i++) {
                        if (*i != heTemp->sPattern[(int) (i - p)]) {
                            bMatch = 0;
                            break;
                        }
                    }
                    if (bMatch) {
                        heTemp->pResolvedAddr = p;
                        fPrintToFile("\t\tFound pattern at %p\n", heTemp->pResolvedAddr);
                        break;
                    }
                }
                p += 1;
            }

            if (heTemp->pResolvedAddr == 0) {
                fPrintToFile("\tPattern not found\n");
                return;
            }

            fSetHook(heTemp);
        }        
    }
}


void* dlopen(const char *filename, int flag) {
    fPrintToFile("\t%04i | %s | %s loaded!\n", getpid(), __progname, filename);
    link_map *result = ((__typeof__(dlopen) *)dlsym(RTLD_NEXT, __FUNCTION__))(filename, flag);
    if (filename == 0) {
        filename = __progname;
    }
    ModuleRange ModRange;

    if (result->l_addr) {
        ModRange.pStart = result->l_addr;
        ModRange.pEnd = result->l_addr+0x1000; // FIXME
        //fSetHooks(__progname, filename, (unsigned char*) result->l_addr);
    } else {
        char progname [256] = {0};
        progname[0] = '/';
        strcpy(&progname[1], __progname);

        fGetModBaseByName(progname, &ModRange);
    }

    fSetHooks(__progname, filename, &ModRange);

    return result;
}