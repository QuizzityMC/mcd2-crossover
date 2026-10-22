#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
typedef unsigned long long U64;typedef uint32_t DWORD;typedef void*H;
#define FAIL ((int)0x80004005)
#define INVALID ((int)0x80070057)
#define NOTIMPL ((int)0x80004001)
#define NOUSER ((int)0x89245100)
static char output[65536];static int enabled=1;static U64 clockMs=100;static int handleMarker,credLock;
static unsigned len(const char*s){return s?(unsigned)strlen(s):0;}
static void append(char*b,unsigned cap,const char*s){size_t n=strlen(b);if(n<cap)snprintf(b+n,cap-n,"%s",s?s:"");}
static unsigned dcDecimal(char*b,unsigned n,U64 v){return n+sprintf(b+n,"%llu",v);}
static unsigned dcLogPrefix(char*b){return sprintf(b,"[t=1792641840000 p=1 th=2] ");}
static int dcLogging(void){return enabled;}
static int dcPath(char*b,unsigned cap,const char*leaf){snprintf(b,cap,"fixture/%s",leaf);return 1;}
static H CreateFileA(const char*a,DWORD b,DWORD c,void*d,DWORD e,DWORD f,H g){return (H)1;}
static int WriteFile(H h,const void*b,DWORD n,DWORD*w,void*x){assert(strlen(output)+n<sizeof(output));strncat(output,b,n);*w=n;return 1;}
static int CloseHandle(H h){return 1;}
static U64 GetTickCount64(void){return clockMs;}
static void AcquireSRWLockExclusive(void*p){}static void ReleaseSRWLockExclusive(void*p){}
#include "../src/runtime-diagnostics.inc"
static void loghr(const char*s,int r){} // Legacy logger isn't under test.
static void nativeHttpObserve(void){} // The independent routed observer has its own tests.
static void*copy(void*d,const void*s,U64 n){return memcpy(d,s,n);}
static int eq(const char*a,const char*b){return a&&b&&!strcmp(a,b);}
static int renewResult,validUser=1,beginResult,allocations;
static struct{char tokens[3][16384];}cred;
static int live(void){return validUser;}static int valid(void*u){return u==&handleMarker&&validUser;}
static int forceRenew(void){clockMs+=23;return renewResult;}
static int initAsync(void){return 1;}
static H GetProcessHeap(void){return (H)1;}
static void*HeapAlloc(H h,DWORD flags,U64 n){allocations++;return calloc(1,n);}
static int HeapFree(H h,DWORD flags,void*p){allocations--;free(p);return 1;}
struct PD;
struct TestAsync {void*context;int(*callback)(unsigned,const struct PD*);int status;U64 size;};
static int abegin(void*a,void*c,const void*identity,const char*name,void*cb){
 if(beginResult)return beginResult;struct TestAsync*t=a;t->context=c;t->callback=cb;t->status=0;return 0;
}
static int aschedule(void*a,unsigned ms){return 0;}
static void acomplete(void*a,int r,U64 n){struct TestAsync*t=a;t->status=r;t->size=n;}
static int asize(void*a,U64*n){*n=((struct TestAsync*)a)->size;return 0;}
static int aresult(void*a,const void*i,U64 n,void*b,U64*used);
#include "../src/token-provider.inc"
#include "../src/token-requests.inc"
static int aresult(void*a,const void*i,U64 n,void*b,U64*used){struct TestAsync*t=a;if(t->status<0)return t->status;if(n<t->size)return INVALID;struct PD d={a,n,b,t->context};int r=t->callback(2,&d);if(used)*used=t->size;return r;}
static void finish(struct TestAsync*t){struct PD d={t,0,0,t->context};assert(t->callback(1,&d)==0);}
static void cleanup(struct TestAsync*t){struct PD d={t,0,0,t->context};assert(t->callback(4,&d)==0);t->context=0;}
int main(void){
 strcpy(cred.tokens[0],"SYNTHETIC_CREDENTIAL_MUST_NOT_APPEAR");
 struct TestAsync a={0},b={0};
 assert(tokenAsync(0,&handleMarker,0,"GET","https://profile.xboxlive.com/users/xuid(PRIVATE_ID)?token=PRIVATE_QUERY",0,0,0,0,&a)==0);
 assert(tokenAsync(0,&handleMarker,1,"GET","https://social.xboxlive.com/users/PRIVATE_ID",0,0,0,0,&b)==0);
 struct Op*oa=a.context,*ob=b.context;assert(oa->diagnostic.id&&ob->diagnostic.id!=oa->diagnostic.id);
 unsigned first=oa->diagnostic.id,second=ob->diagnostic.id;
 finish(&b);finish(&a);char buffer[32768];void*ptr=0;
 assert(tokenResult(0,&a,sizeof(buffer),buffer,&ptr,0)==0&&ptr==buffer);
 assert(((struct TokenData*)buffer)->signatureSize==0);
 assert(!strcmp(((struct TokenData*)buffer)->token,cred.tokens[0]));
 char expect[100];sprintf(expect,"event=complete id=%u host=profile.xboxlive.com",first);assert(strstr(output,expect));
 sprintf(expect,"event=complete id=%u host=social.xboxlive.com",second);assert(strstr(output,expect));
 assert(strstr(output,"signature=absent")&&strstr(output,"refresh=1"));cleanup(&a);cleanup(&b);
 unsigned short url[]={ 'h','t','t','p','s',':','/','/','p','r','o','f','i','l','e','.','x','b','o','x','l','i','v','e','.','c','o','m','/',0};
 unsigned short method[]={'G','E','T',0};
 assert(token16(0,&handleMarker,0,method,url,0,0,0,0,&a)==0);finish(&a);cleanup(&a);
 renewResult=FAIL;assert(tokenAsync(0,&handleMarker,1,"GET","https://profile.xboxlive.com/",0,0,0,0,&a)==0);finish(&a);assert(a.status==FAIL);cleanup(&a);
 assert(strstr(output,"hr=80004005"));renewResult=0;
 beginResult=FAIL;assert(tokenAsync(0,&handleMarker,0,"GET","https://profile.xboxlive.com/",0,0,0,0,&a)==FAIL);beginResult=0;
 assert(tokenAsync(0,&handleMarker,8,"GET","https://profile.xboxlive.com/",0,0,0,0,&a)==NOTIMPL);
 assert(tokenAsync(0,(void*)123,0,"GET","https://profile.xboxlive.com/",0,0,0,0,&a)==NOUSER);
 assert(tokenAsync(0,&handleMarker,0,"GET","https://PRIVATE_HOST.invalid/",0,0,0,0,&a)==NOTIMPL);
 nativeFailure((int)0x80190191);assert(strstr(output,"operation=async-status correlation=unavailable hr=80190191 http=401"));
 assert(!strstr(output,"SYNTHETIC_CREDENTIAL")&&!strstr(output,"PRIVATE_ID")&&!strstr(output,"PRIVATE_QUERY")&&!strstr(output,"PRIVATE_HOST"));
 assert(allocations==0);
 puts(output);enabled=0;output[0]=0;
 assert(tokenAsync(0,&handleMarker,0,"GET","https://profile.xboxlive.com/",0,0,0,0,&a)==0);finish(&a);cleanup(&a);nativeFailure(FAIL);
 assert(output[0]==0&&allocations==0);
 puts("token lifecycle checks passed");
}
