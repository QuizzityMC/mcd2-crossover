/* Compile-only x64 Windows ABI/freestanding check. Never executed. */
typedef unsigned long DWORD;
typedef unsigned long long U64;
typedef void* H;
#define IMP __declspec(dllimport)
IMP void* GetProcAddress(H,const char*);
IMP void AcquireSRWLockExclusive(void*);
IMP void ReleaseSRWLockExclusive(void*);
IMP H CreateFileA(const char*,DWORD,DWORD,void*,DWORD,DWORD,H);
IMP int WriteFile(H,const void*,DWORD,DWORD*,void*);
IMP int CloseHandle(H);
IMP H CreateThread(void*,U64,DWORD(*)(void*),void*,DWORD,DWORD*);
IMP U64 GetTickCount64(void);
/* These are integration dependencies, deliberately unresolved in this object. */
int dcLogging(void);
int dcPath(char*,unsigned,const char*);
unsigned dcLogPrefix(char*);
unsigned dcDecimal(char*,unsigned,U64);
unsigned len(const char*);
void append(char*,unsigned,const char*);
void* memset(void*p,int c,U64 n){volatile unsigned char*b=p;while(n--)*b++=(unsigned char)c;return p;}
#include "../src/runtime-diagnostics.inc"
#include "../src/native-http-diagnostics.inc"
void nativeHttpCompileProbe(void){nativeHttpObserve();}
