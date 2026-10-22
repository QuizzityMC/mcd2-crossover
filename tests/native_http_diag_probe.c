/* Execute production include and parent serializers against a stub DLL API.
 * No game, network, credentials, Windows runtime or real DLL is loaded. */
#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef uint32_t DWORD;
typedef unsigned long long U64;
typedef void* H;
#define IMP
static pthread_mutex_t apiLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t outputLock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic int recording=1;
static DWORD (*queuedWorker)(void*);
static void* queuedContext;
static _Atomic int threadCreates,threadCloses;
static int threadFail,realWorkerMode;
static int selfPinFail,targetPinFail,exportPinFail,pinApiMissing,selfPinned,targetPinned,exportPins,toggleOffInAdd;
static pthread_t workerThread,initOwner;
static pthread_mutex_t hcInitLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t entryLock=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t entryCondition=PTHREAD_COND_INITIALIZER;
static int workerEntered;
static char output[262144];
static unsigned len(const char*s){return s?(unsigned)strlen(s):0;}
static void append(char*b,unsigned cap,const char*s){size_t n=strlen(b);while(s&&*s&&n+1<cap)b[n++]=*s++;b[n]=0;}
static unsigned dcDecimal(char*b,unsigned n,U64 value){return n+(unsigned)snprintf(b+n,32,"%llu",value);}
static int dcLogging(void){return recording;}
static int dcPath(char*b,unsigned n,const char*s){assert(!strcmp(s,"runtime.log"));snprintf(b,n,"runtime.log");return 1;}
static unsigned dcLogPrefix(char*b){strcpy(b,"[t=1792641840793 p=1492 th=1496] ");return (unsigned)strlen(b);}
static H CreateFileA(const char*p,DWORD a,DWORD b,void*c,DWORD d,DWORD e,H f){(void)p;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return (H)1;}
static int WriteFile(H h,const void*b,DWORD n,DWORD*w,void*x){
 (void)h;(void)x;pthread_mutex_lock(&outputLock);size_t used=strlen(output);assert(used+n<sizeof(output));memcpy(output+used,b,n);output[used+n]=0;*w=n;pthread_mutex_unlock(&outputLock);return 1;
}
static int CloseHandle(H h){if(h==(H)0x55)threadCloses++;return 1;}
static void* workerMain(void*p){(void)p;queuedWorker(queuedContext);return 0;}
static H CreateThread(void*a,U64 size,DWORD(*fn)(void*),void*ctx,DWORD flags,DWORD*id){
 (void)a;(void)size;(void)flags;(void)id;threadCreates++;if(threadFail)return 0;
 assert(selfPinned);assert(!queuedWorker);queuedWorker=fn;queuedContext=ctx;
 if(realWorkerMode)assert(!pthread_create(&workerThread,0,workerMain,0));return (H)0x55;
}
static U64 GetTickCount64(void){return 1234;}
static void AcquireSRWLockExclusive(void*p){(void)p;assert(!pthread_mutex_lock(&apiLock));}
static void ReleaseSRWLockExclusive(void*p){(void)p;assert(!pthread_mutex_unlock(&apiLock));}
H GetModuleHandleA(const char*);
void* GetProcAddress(H,const char*);
#include "../src/runtime-diagnostics.inc"
#include "../src/native-http-diagnostics.inc"

struct Call {
 U64 id;const char *method,*url,*body,*header;
 unsigned status,platform;int network,urlHr,statusHr,networkHr,sizeHr,bytesHr,headerHr;
 U64 size,usedOverride;int overrideUsed;
};
static struct Call sample;
static int modulePresent=1,addReturn,reentrant;
static _Atomic int addCalls,lookupCalls,resolveCalls,bodyReads,sizeReads,headerReads;
static const char*missing;
static NativeHttpRouted routed;
static void* routedContext;
static int stubAdd(NativeHttpRouted cb,void*ctx){
 if(realWorkerMode){
  /* The old synchronous observer would re-enter on initOwner and fail here. */
  assert(!pthread_equal(pthread_self(),initOwner));
  pthread_mutex_lock(&entryLock);workerEntered=1;pthread_cond_signal(&entryCondition);pthread_mutex_unlock(&entryLock);
  assert(!pthread_mutex_lock(&hcInitLock));assert(!pthread_mutex_unlock(&hcInitLock));
 }
 assert(selfPinned&&targetPinned&&exportPins>=8);addCalls++;if(addReturn<0)return addReturn;
 routed=cb;routedContext=ctx;
 /* Prove publication and lock ordering if a callback happens before return. */
 if(reentrant){nativeHttpObserve();cb(&sample,ctx);}
 if(toggleOffInAdd)recording=0;return addReturn;
}
static U64 stubId(void*p){return ((struct Call*)p)->id;}
static int stubUrl(void*p,const char**method,const char**url){struct Call*c=p;if(c->urlHr<0)return c->urlHr;*method=c->method;*url=c->url;return 0;}
static int stubStatus(void*p,unsigned*s){struct Call*c=p;if(c->statusHr<0)return c->statusHr;*s=c->status;return 0;}
static int stubNetwork(void*p,int*n,unsigned*platform){struct Call*c=p;if(c->networkHr<0)return c->networkHr;*n=c->network;*platform=c->platform;return 0;}
static int stubSize(void*p,U64*n){struct Call*c=p;sizeReads++;if(c->sizeHr<0)return c->sizeHr;*n=c->size;return 0;}
static int stubBytes(void*p,U64 n,unsigned char*b,U64*used){
 struct Call*c=p;bodyReads++;if(c->bytesHr<0)return c->bytesHr;
 assert(n==4096);assert(c->size<=n);if(c->size)memcpy(b,c->body,(size_t)c->size);
 *used=c->overrideUsed?c->usedOverride:c->size;return 0;
}
static int stubHeader(void*p,const char*name,const char**v){
 struct Call*c=p;headerReads++;assert(!strcmp(name,"x-request-id")||!strcmp(name,"request-id")||!strcmp(name,"x-ms-request-id"));
 if(c->headerHr<0)return c->headerHr;*v=!strcmp(name,"x-request-id")?c->header:0;return 0;
}
static int stubPin(DWORD flags,const char*name,H*out){
 assert(flags==1||flags==5);*out=0;
 if(flags==1){assert(!strcmp(name,"libHttpClient.GDK.dll"));if(!modulePresent||targetPinFail)return 0;targetPinned=1;*out=(H)0x1234;return 1;}
 if(name==(const char*)&nativeHttpLock){if(selfPinFail)return 0;selfPinned=1;*out=(H)0x2222;return 1;}
 if(exportPinFail)return 0;exportPins++;*out=(H)0x3333;return 1;
}
static int stubCanUnload(void){return 0;}
H GetModuleHandleA(const char*name){lookupCalls++;assert(!strcmp(name,"kernel32.dll"));return (H)0x9999;}
void* GetProcAddress(H module,const char*name){
 if(module==(H)0x9999){assert(!strcmp(name,"GetModuleHandleExA"));return pinApiMissing?0:(void*)stubPin;}
 if(module==(H)0x1235){assert(!strcmp(name,"DllCanUnloadNow"));return (void*)stubCanUnload;}
 assert(module==(H)0x1234);resolveCalls++;if(missing&&!strcmp(name,missing))return 0;
 if(!strcmp(name,"HCAddCallRoutedHandler"))return (void*)stubAdd;
 if(!strcmp(name,"HCHttpCallGetId"))return (void*)stubId;
 if(!strcmp(name,"HCHttpCallRequestGetUrl"))return (void*)stubUrl;
 if(!strcmp(name,"HCHttpCallResponseGetStatusCode"))return (void*)stubStatus;
 if(!strcmp(name,"HCHttpCallResponseGetNetworkErrorCode"))return (void*)stubNetwork;
 if(!strcmp(name,"HCHttpCallResponseGetResponseBodyBytesSize"))return (void*)stubSize;
 if(!strcmp(name,"HCHttpCallResponseGetResponseBodyBytes"))return (void*)stubBytes;
 if(!strcmp(name,"HCHttpCallResponseGetHeader"))return (void*)stubHeader;
 assert(!"unexpected export: no initialization, tracing, raw strings or mutation allowed");return 0;
}
static void drainWorker(void){
 if(!queuedWorker)return;
 if(realWorkerMode)assert(!pthread_join(workerThread,0));else queuedWorker(queuedContext);
 queuedWorker=0;queuedContext=0;
}
static void observe(void){nativeHttpObserve();drainWorker();}
static void reset(void){
 assert(!queuedWorker);threadCreates=threadCloses=0;threadFail=realWorkerMode=workerEntered=0;
 memset(&nativeHttpApi,0,sizeof(nativeHttpApi));memset(nativeHttpCalls,0,sizeof(nativeHttpCalls));
 nativeHttpRegistering=nativeHttpRegistrationSucceeded=nativeHttpSelfPinned=0;
 selfPinFail=targetPinFail=exportPinFail=pinApiMissing=selfPinned=targetPinned=exportPins=toggleOffInAdd=0;
 recording=modulePresent=1;addReturn=addCalls=lookupCalls=resolveCalls=bodyReads=sizeReads=headerReads=reentrant=0;
 missing=0;routed=0;routedContext=0;output[0]=0;
 memset(&sample,0,sizeof(sample));sample.id=18446744073709551614ULL;sample.method="GET";
 sample.url="https://profile.xboxlive.com/users/PRIVATE_ID/profile?token=QUERY_SECRET";
 sample.status=401;sample.body="{\"error\":\"InvalidToken\",\"secret\":\"BODY_SECRET\"}";sample.size=strlen(sample.body);
 sample.header="12345678-1234-1234-1234-123456789abc";
}
static void has(const char*s){if(!strstr(output,s)){fprintf(stderr,"missing %s in:\n%s",s,output);abort();}}
static void lacks(const char*s){if(strstr(output,s)){fprintf(stderr,"unexpected %s in:\n%s",s,output);abort();}}
static unsigned count(const char*s){unsigned n=0;const char*p=output;while((p=strstr(p,s))){n++;p+=strlen(s);}return n;}
static void fire(void){assert(routed);routed(&sample,routedContext);}
static void* observeThread(void*p){(void)p;for(int i=0;i<50;i++)nativeHttpObserve();return 0;}
static void* resultThread(void*p){(void)p;for(int i=0;i<10;i++)fire();return 0;}
#ifdef NATIVE_HTTP_RUNTIME_INIT_INCLUDE
static H self,real=(H)0x1235;
static int ensureReal(void){return 1;}
static DWORD GetModuleFileNameA(H m,char*b,DWORD n){(void)m;const char*p="C:\\game\\xgameruntime.dll";assert(strlen(p)+1<n);strcpy(b,p);return (DWORD)strlen(p);}
static int stubNativeInit(U64 a,U64 b,U64 mode,void*options){(void)a;(void)b;(void)mode;(void)options;return 0;}
static int (*nativeInit)(U64,U64,U64,void*)=stubNativeInit;
static void loghr(const char*m,int hr){(void)m;(void)hr;}
#include NATIVE_HTTP_RUNTIME_INIT_INCLUDE
static void initializationRegression(void){
 reset();realWorkerMode=1;initOwner=pthread_self();
 assert(!pthread_mutex_lock(&hcInitLock));
 /* HCInitialize owns its singleton mutex while invoking the actual adapter
  * initializer. Native init success must not trigger HTTP observation. */
 assert(InitializeApiImplEx2(0,0,0,0)==0);
 assert(!threadCreates&&!addCalls&&!lookupCalls);
 /* Even a later observation from a caller holding a library lock must return
  * immediately. Worker reaches add on another thread and blocks on that lock. */
 nativeHttpObserve();assert(threadCreates==1&&threadCloses==1);
 pthread_mutex_lock(&entryLock);
 while(!workerEntered)pthread_cond_wait(&entryCondition,&entryLock);
 pthread_mutex_unlock(&entryLock);
 assert(!addCalls);
 /* Many requests while registration is blocked must not create more workers. */
 for(unsigned i=0;i<100;i++)nativeHttpObserve();assert(threadCreates==1);
 assert(!pthread_mutex_unlock(&hcInitLock));drainWorker();
 assert(addCalls==1&&nativeHttpRegistrationSucceeded);fire();has("http=401");
 reset();threadFail=1;nativeHttpObserve();assert(!queuedWorker&&!nativeHttpRegistering);
 has("coverage=registration-failed hr=80004005");threadFail=0;observe();assert(nativeHttpRegistrationSucceeded);
 reset();nativeHttpObserve();assert(queuedWorker&&!addCalls);
 output[0]=0;int before=lookupCalls;recording=0;drainWorker();assert(!addCalls&&lookupCalls==before&&!nativeHttpRegistering&&!output[0]);
 recording=1;observe();assert(nativeHttpRegistrationSucceeded);
 puts("initialization reentry and deferred worker regression: ok");
}
#else
static void initializationRegression(void){fputs("Use test_native_http_observer.py to include the production initializer\n",stderr);exit(2);}
#endif
static void lifetimeAndCoverageTests(void){
 reset();assert(!nativeHttpCannotUnload());
#ifdef NATIVE_HTTP_RUNTIME_INIT_INCLUDE
 assert(DllCanUnloadNow()==0);
#endif
 nativeHttpObserve();assert(queuedWorker&&!addCalls);has("coverage=pending");
 assert(selfPinned&&nativeHttpCannotUnload());
#ifdef NATIVE_HTTP_RUNTIME_INIT_INCLUDE
 assert(DllCanUnloadNow()==1);
#endif
 /* A request completes before registration: there is no callback to invoke.
  * pending evidence survives, and we neither block nor invent its result. */
 unsigned missed=0;if(routed)fire();else missed++;
 assert(missed==1);lacks("event=result");drainWorker();assert(addCalls==1);
 fire();has("http=401");has("coverage=registered");assert(nativeHttpCannotUnload());
 /* Simulate HC cleanup/reinit erasing registry while DLL remains pinned.
  * Subsequent registered rows are historical only; no fabricated HTTP results
  * or inferred live registry, and no duplicate registration is attempted. */
 routed=0;output[0]=0;observe();assert(addCalls==1&&!routed);has("coverage=registered");lacks("event=result");
 reset();pinApiMissing=1;observe();has("coverage=registration-failed");assert(!threadCreates&&!addCalls&&!nativeHttpCannotUnload());
 reset();selfPinFail=1;observe();assert(!threadCreates&&!addCalls&&!nativeHttpCannotUnload());
 reset();targetPinFail=1;observe();assert(!addCalls&&nativeHttpCannotUnload());has("coverage=module-missing");
 reset();exportPinFail=1;observe();assert(!addCalls&&nativeHttpCannotUnload());has("coverage=registration-failed");
 /* Registration finishes during OFF: its historical success must be emitted
  * on the next ON observation, even if no observe call witnessed OFF. */
 reset();toggleOffInAdd=1;observe();assert(nativeHttpRegistrationSucceeded&&!recording);lacks("coverage=registered");
 recording=1;output[0]=0;observe();has("coverage=registered");assert(addCalls==1);
 output[0]=0;observe();has("coverage=registered");assert(addCalls==1);
 puts("pending gap, module pinning, unload refusal, historical registry and logging race: ok");
}
static void registrationTests(void){
 reset();modulePresent=0;observe();has("coverage=module-missing hr=8007007E");assert(!resolveCalls&&!addCalls);
 observe();assert(count("coverage=module-missing")==2);
 modulePresent=1;observe();has("coverage=registered hr=00000000");assert(addCalls==1); /* zero ID valid */
 for(int i=0;i<10;i++)observe();assert(addCalls==1);
 const char*symbols[]={"HCAddCallRoutedHandler","HCHttpCallGetId","HCHttpCallRequestGetUrl","HCHttpCallResponseGetStatusCode","HCHttpCallResponseGetNetworkErrorCode","HCHttpCallResponseGetResponseBodyBytesSize","HCHttpCallResponseGetResponseBodyBytes","HCHttpCallResponseGetHeader"};
 for(unsigned i=0;i<8;i++){reset();missing=symbols[i];observe();has("coverage=exports-missing hr=8007007F");assert(!addCalls);missing=0;observe();assert(addCalls==1);}
 reset();addReturn=-1;observe();has("coverage=registration-failed hr=80004005");assert(!nativeHttpRegistrationSucceeded);
 addReturn=(int)0x89235001U;observe();has("coverage=registration-failed hr=89235001");
 addReturn=17;observe();has("coverage=registered");assert(nativeHttpRegistrationSucceeded);
 reset();reentrant=1;observe();has("event=result");assert(addCalls==1);
 reset();pthread_t threads[16];for(int i=0;i<16;i++)assert(!pthread_create(&threads[i],0,observeThread,0));
 for(int i=0;i<16;i++)assert(!pthread_join(threads[i],0));drainWorker();assert(threadCreates==1&&threadCloses==1);assert(addCalls==1);assert(count("coverage=registered")==1);
 for(int i=0;i<16;i++)assert(!pthread_create(&threads[i],0,resultThread,0));
 for(int i=0;i<16;i++)assert(!pthread_join(threads[i],0));assert(count("event=result")==160);has("retry=159 correlation=exact");
}
static void privacyTests(void){
 reset();observe();fire();has("source=native-http id=18446744073709551614");has("host=profile.xboxlive.com operation=profile method=GET http=401 hr=00000000 error_code=0 error=InvalidToken");
 has("response=json request_id=12345678-1234-1234-1234-123456789abc retry=0 correlation=exact");
 lacks("PRIVATE_ID");lacks("QUERY_SECRET");lacks("BODY_SECRET");lacks("final");
 output[0]=0;fire();has("retry=1 correlation=exact");
 output[0]=0;sample.url="https://PRIVATE@profile.xboxlive.com/";sample.method="SECRET_METHOD";sample.header="HEADER_SECRET";
 sample.body="{\"error\":\"SECRET_ERROR\",\"token\":\"SECRET_TOKEN\"}";sample.size=strlen(sample.body);fire();
 has("host=other operation=other method=other");has("error=other response=json request_id=absent");lacks("SECRET");lacks("PRIVATE");
 output[0]=0;sample.body="{\"nested\":{\"error\":\"InvalidToken\"}}";sample.size=strlen(sample.body);fire();has("error=none");lacks("error=InvalidToken");
 output[0]=0;sample.body="<html>InvalidToken SECRET</html>";sample.size=strlen(sample.body);fire();has("error=other response=markup");lacks("InvalidToken");
 output[0]=0;sample.status=200;sample.header="12345678-1234-1234-1234-123456789abc";int before=bodyReads,beforeSize=sizeReads;fire();
 assert(bodyReads==before&&sizeReads==beforeSize);has("error=none response=unobserved request_id=12345678-1234-1234-1234-123456789abc");
 /* A UUID followed by arbitrary suffix is never accepted as a prefix. */
 output[0]=0;sample.header="12345678-1234-1234-1234-123456789abcSECRET";fire();has("request_id=absent");lacks("SECRET");
 output[0]=0;recording=0;before=lookupCalls;int resolves=resolveCalls;observe();fire();assert(!output[0]&&lookupCalls==before&&resolveCalls==resolves);
 recording=1;observe();has("coverage=registered");assert(addCalls==1);
 reset();recording=0;observe();assert(!output[0]&&!lookupCalls&&!addCalls);recording=1;observe();has("coverage=registered");
}
static void getterTests(void){
 reset();observe();output[0]=0;sample.network=(int)0x80072EE7U;sample.platform=0x80072EE7U;sample.status=0;fire();
 has("http=0 hr=80072EE7 error_code=-2147012889");
 output[0]=0;sample.statusHr=(int)0x80004005U;sample.networkHr=(int)0x80070057U;sample.urlHr=(int)0x80004005U;fire();
 has("host=other operation=other method=other hr=80004005");lacks(" http=");lacks(" error_code=");
 output[0]=0;sample.id=0;fire();has("event=failure source=native-http correlation=unavailable hr=80070057");lacks("correlation=exact");
 reset();observe();sample.sizeHr=(int)0x80004005U;output[0]=0;fire();has("response=unobserved");assert(!bodyReads);
 sample.sizeHr=0;sample.bytesHr=(int)0x80004005U;output[0]=0;fire();has("response=unobserved");
 sample.bytesHr=0;sample.overrideUsed=1;sample.usedOverride=4097;output[0]=0;fire();has("response=unobserved");
 sample.overrideUsed=0;sample.size=0;output[0]=0;fire();has("error=none response=empty");
}
static void boundedTests(void){
 reset();observe();long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
 char*map=mmap(0,(size_t)page*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);assert(map!=MAP_FAILED);
 assert(!mprotect(map+page,(size_t)page,PROT_NONE));
 /* An exact 4096-byte non-NUL body ends against a guard page. */
 char*body=map+page-4096;memset(body,'S',4096);memcpy(body,"{\"error\":\"InvalidToken\",\"x\":\"",29);body[4094]='"';body[4095]='}';
 sample.body=body;sample.size=4096;output[0]=0;fire();has("error=InvalidToken");lacks("SSSS");
 /* Oversize body must not even invoke the bytes getter or dereference body. */
 int reads=bodyReads;sample.body=map+page;sample.size=4097;output[0]=0;fire();assert(bodyReads==reads);has("response=unobserved");
 sample.size=~0ULL;fire();assert(bodyReads==reads);
 /* Getter strings are NUL terminated, but may exceed our privacy bounds. */
 memset(map+page-80,'S',80);sample.header=map+page-80;sample.status=200;output[0]=0;fire();has("request_id=absent");
 memset(map+page-2048,'S',2048);sample.url=map+page-2048;sample.header=0;output[0]=0;fire();has("host=other");lacks("SSSS");
 assert(!munmap(map,(size_t)page*2));
 /* Bound retry tracking without recycling IDs and inventing retry zero. */
 reset();observe();sample.status=200;sample.header=0;
 for(unsigned i=1;i<=257;i++){sample.id=i;output[0]=0;fire();if(i==256)has("retry=0");if(i==257)lacks(" retry=");}
 sample.id=1;output[0]=0;fire();has("retry=1");
}
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"--emit-fixture")){reset();observe();fire();fire();fputs(output,stdout);return 0;}
 initializationRegression();lifetimeAndCoverageTests();registrationTests();privacyTests();getterTests();boundedTests();puts("native HTTP routed diagnostics: ok");return 0;
}
