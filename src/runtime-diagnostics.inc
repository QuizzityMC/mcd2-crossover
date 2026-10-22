#include "diagnostic.inc"
/* IDs identify observations within one process and layer. They are never
 * pointers or account IDs. No timestamp-based causal association is made. */
static U64 diagLock;
static unsigned diagSequence;
struct TokenTrace {unsigned id;U64 started;char host[96],operation[48],method[16];unsigned refresh;};
static void diagWrite(const char*row){
 if(!dcLogging())return;char path[2048]={0},line[1024]={0};if(!dcPath(path,sizeof(path),"runtime.log"))return;
 dcLogPrefix(line);append(line,sizeof(line),row);append(line,sizeof(line)," build=20261022.2\r\n");
 H f=CreateFileA(path,4,3,0,4,128,0);if(f!=(H)-1){DWORD w;WriteFile(f,line,len(line),&w,0);CloseHandle(f);}
}
static void diagNumber(char*b,unsigned cap,const char*key,U64 value){char number[32]={0};unsigned n=dcDecimal(number,0,value);number[n]=0;append(b,cap,key);append(b,cap,number);}
static void diagHex(char*b,unsigned cap,int value){char h[9]={0};for(unsigned i=0;i<8;i++)h[i]="0123456789ABCDEF"[((unsigned)value>>(28-i*4))&15];append(b,cap," hr=");append(b,cap,h);}
static void tokenTraceEmit(const struct TokenTrace*t,const char*event,int hr){
 if(!t->id)return;char b[768]={0};append(b,sizeof(b),"diag v=1 layer=token event=");append(b,sizeof(b),event);
 diagNumber(b,sizeof(b)," id=",t->id);append(b,sizeof(b)," host=");append(b,sizeof(b),t->host);
 append(b,sizeof(b)," operation=");append(b,sizeof(b),t->operation);append(b,sizeof(b)," method=");append(b,sizeof(b),t->method);
 diagNumber(b,sizeof(b)," refresh=",t->refresh);append(b,sizeof(b)," signature=absent correlation=exact");diagHex(b,sizeof(b),hr);
 U64 elapsed=GetTickCount64()-t->started;diagNumber(b,sizeof(b)," elapsed_ms=",elapsed>86400000?86400000:elapsed);diagWrite(b);
}
static void tokenTraceStart(struct TokenTrace*t,const char*url,const char*method,unsigned opts){
 memset(t,0,sizeof(*t));if(!dcLogging())return;
 AcquireSRWLockExclusive(&diagLock);t->id=++diagSequence;ReleaseSRWLockExclusive(&diagLock);
 t->started=GetTickCount64();dcDiagRoute(url,t->host,t->operation);dcDiagCopy(t->method,sizeof(t->method),dcDiagMethod(method));t->refresh=opts&1;
 tokenTraceEmit(t,"start",0);
}
static void nativeFailure(int hr){
 if(!dcLogging())return;unsigned id;AcquireSRWLockExclusive(&diagLock);id=++diagSequence;ReleaseSRWLockExclusive(&diagLock);
 char b[512]={0};append(b,sizeof(b),"diag v=1 layer=native event=failure");diagNumber(b,sizeof(b)," id=",id);
 append(b,sizeof(b)," host=other operation=async-status correlation=unavailable");diagHex(b,sizeof(b),hr);
 if(((unsigned)hr&0xffff0000U)==0x80190000U)diagNumber(b,sizeof(b)," http=",(unsigned)hr&0xffffU);
 diagWrite(b);
}
