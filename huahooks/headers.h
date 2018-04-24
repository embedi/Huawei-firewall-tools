#define UINT8  unsigned char
#define UINT16 unsigned short
#define UINT32 unsigned int
#define UINT64 unsigned long long

#define INIT_HOOK(lib, func) _##func = dlsym(lib, #func)

typedef void (*callback_function)(void);

typedef struct {
    char sProgName [64];
    char sModName [64];
    unsigned char sPattern [128];
    int  iPatternLen;
    unsigned char sProlog [128];
    unsigned char sHook[32];
    callback_function pfnCallback;
    void* pResolvedAddr;
} HOOK_ENTRY;