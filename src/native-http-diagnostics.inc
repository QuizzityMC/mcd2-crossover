/* Official libHttpClient routed observer; include AFTER runtime-diagnostics.inc.
 * Call nativeHttpObserve() outside DllMain from token/status paths, NEVER from
 * InitializeApiImplEx2: it can be nested inside HCInitialize's singleton lock.
 * Observe schedules a worker and never waits for it. Only the worker enters
 * libHttpClient, so an outer library lock cannot be recursively acquired by
 * the calling thread. No sleeps, polling, new HC initialization or wait APIs.
 * The adapter is pinned before dispatch; the target and resolved export modules
 * are pinned on the worker before registration. DllCanUnloadNow refuses unload
 * while a worker is claimed or once pinning has succeeded. No initialization,
 * tracing, transport or callback replacement.
 * coverage=pending explicitly exposes requests that can finish before registration.
 * coverage=registered is ONLY historical success of HCAddCallRoutedHandler.
 * HC cleanup/reinit can erase handlers without unloading the DLL: no registry
 * liveness, complete capture or automatic re-registration is inferred here.
 *
 * ABI/semantics verified against Microsoft libHttpClient commit
 * 3df5588fc073620caad1dfa7dac5a011d933f7a8:
 * Include/httpClient/httpClient.h:190-213,306,686-722,738-751,774
 * Include/httpClient/httpProvider.h:108 (GetUrl has THREE arguments).
 * Source/Global/global_publics.cpp:145 (signed handler ID; 0 is valid,
 *   negative means failure, including E_HC_NOT_INITIALISED).
 * Source/HTTP/httpcall.cpp:321 (callback AFTER individual attempt, BEFORE retry).
 * Source/HTTP/httpcall_response.cpp:56,109,238,318.
 * https://github.com/microsoft/libHttpClient/tree/3df5588fc073620caad1dfa7dac5a011d933f7a8
 *
 * Each result is an observation, NOT a final operation outcome. id is the
 * library's HTTP call ID, scoped by source+pid+layer. retry is the zero-based
 * OBSERVED callback ordinal for that call, not an authoritative retry count.
 * When the bounded table fills, omit retry for new IDs rather than invent it.
 * There is NO association with a token or parent XAsyncBlock.
 *
 * Body access uses size + bounded bytes getters. The string getter is deliberately
 * NOT used: the verified implementation can trace raw response text itself.
 */
IMP H GetModuleHandleA(const char*);
#if defined(_WIN32)
#define NHTTP_CALL __stdcall
#else
#define NHTTP_CALL
#endif
typedef void (NHTTP_CALL *NativeHttpRouted)(void*,void*);
typedef char NativeHttpRequiresX64[(sizeof(void*)==8&&sizeof(U64)==8&&sizeof(int)==4&&sizeof(unsigned)==4)?1:-1];
struct NativeHttpApi {
 int (NHTTP_CALL *add)(NativeHttpRouted,void*);
 U64 (NHTTP_CALL *id)(void*);
 int (NHTTP_CALL *url)(void*,const char**,const char**);
 int (NHTTP_CALL *status)(void*,unsigned*);
 int (NHTTP_CALL *network)(void*,int*,unsigned*);
 int (NHTTP_CALL *bodySize)(void*,U64*);
 int (NHTTP_CALL *bodyBytes)(void*,U64,unsigned char*,U64*);
 int (NHTTP_CALL *header)(void*,const char*,const char**);
};
static struct NativeHttpApi nativeHttpApi;
static U64 nativeHttpLock;
static int nativeHttpRegistering,nativeHttpRegistrationSucceeded,nativeHttpSelfPinned;
static struct {U64 id;unsigned observation;} nativeHttpCalls[256];

/* Called with nativeHttpLock held. diagWrite honors the recording gate. */
static void nativeHttpCoverageRow(unsigned state,int hr){
 static const char*names[]={"disabled","registered","module-missing","exports-missing","registration-failed","pending"};
 /* Deliberately do not cache emission. diagWrite can suppress a row if the
  * recording flag changes between these calls. A later observation must retry
  * the historical evidence, even when no caller observed the intervening OFF. */
 char b[256]={0};append(b,sizeof(b),"diag v=1 layer=http event=coverage source=native-http coverage=");
 append(b,sizeof(b),names[state]);diagHex(b,sizeof(b),hr);diagWrite(b);
}
/* Official GetModuleHandleExA ABI/flags (Microsoft libloaderapi.h):
 * PIN=1 keeps a loaded module until process termination; FROM_ADDRESS=4 pins
 * the module containing the supplied address. Never UNCHANGED_REFCOUNT=2.
 * Resolve from resident kernel32 without adding a new static import requirement.
 * All calls are outside DllMain. This does not load a missing target DLL.
 * https://learn.microsoft.com/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandleexa */
static int nativeHttpPin(DWORD flags,const char*name,H*out){
 H kernel=GetModuleHandleA("kernel32.dll");if(!kernel)return 0;
 int(NHTTP_CALL *pin)(DWORD,const char*,H*)=(int(NHTTP_CALL *)(DWORD,const char*,H*))GetProcAddress(kernel,"GetModuleHandleExA");
 return pin&&pin(flags,name,out);
}
static int nativeHttpCannotUnload(void){
 AcquireSRWLockExclusive(&nativeHttpLock);
 int busy=nativeHttpRegistering||nativeHttpSelfPinned;
 ReleaseSRWLockExclusive(&nativeHttpLock);return busy;
}
/* Never read more than cap bytes from an official NUL-terminated getter result.
 * Refuse a truncated value instead of emitting a misleading host or UUID. */
static int nativeHttpCopy(char*out,unsigned cap,const char*in){
 if(!in){out[0]=0;return 0;}
 for(unsigned i=0;i<cap;i++){char c=in[i];if(!c){out[i]=0;return 1;}if(i+1<cap)out[i]=c;}
 out[0]=0;return 0;
}
static void NHTTP_CALL nativeHttpResult(void*call,void*context){
 (void)context;if(!dcLogging())return;
 U64 id=nativeHttpApi.id(call);
 if(!id){char b[256]={0};append(b,sizeof(b),"diag v=1 layer=http event=failure source=native-http correlation=unavailable");diagHex(b,sizeof(b),(int)0x80070057U);diagWrite(b);return;}
 unsigned retry=0;int tracked=0;
 AcquireSRWLockExclusive(&nativeHttpLock);
 unsigned empty=256;
 for(unsigned i=0;i<256;i++){
  if(nativeHttpCalls[i].id==id){retry=nativeHttpCalls[i].observation;tracked=1;if(retry<0x7fffffffU)nativeHttpCalls[i].observation++;else tracked=0;break;}
  if(!nativeHttpCalls[i].id&&empty==256)empty=i;
 }
 if(!tracked&&empty<256){nativeHttpCalls[empty].id=id;nativeHttpCalls[empty].observation=1;tracked=1;}
 ReleaseSRWLockExclusive(&nativeHttpLock);
 const char*url=0,*method=0;char urlCopy[2048]={0},methodCopy[16]={0},host[96],operation[48];
 int urlHr=nativeHttpApi.url(call,&method,&url);
 if(urlHr>=0){nativeHttpCopy(urlCopy,sizeof(urlCopy),url);nativeHttpCopy(methodCopy,sizeof(methodCopy),method);}
 dcDiagRoute(urlCopy,host,operation);
 unsigned status=0,platform=0;int network=0;
 int statusHr=nativeHttpApi.status(call,&status),networkHr=nativeHttpApi.network(call,&network,&platform);
 /* hr is network HRESULT on a successful getter; otherwise getter failure.
  * error_code is the platform code as signed int32 bit pattern, not Xbox XErr.
  * Omit http/error_code if their getters failed; never report fabricated zeros. */
 int hr=urlHr<0?urlHr:statusHr<0?statusHr:networkHr<0?networkHr:network;
 const char*response="unobserved";char error[64]="none",requestId[37]={0};
 if(statusHr>=0&&status>=400&&status<=599){
  dcDiagCopy(error,sizeof(error),"other");U64 size=0,used=0;
  if(nativeHttpApi.bodySize(call,&size)>=0&&size<=4096){
   if(!size){response="empty";dcDiagCopy(error,sizeof(error),"none");}
   else{
    unsigned char body[4097]={0};
    if(nativeHttpApi.bodyBytes(call,4096,body,&used)>=0&&used==size){
     body[used]=0;const char*p=(const char*)body;
     while(*p==' '||*p=='\t'||*p=='\r'||*p=='\n')p++;
     response=*p=='{'?"json":*p=='<'?"markup":*p?"other":"empty";
     /* Only fixed root error/code identifiers; never retain the body. */
     if(*p=='{')dcDiagError(p,error);
    }
    memset(body,0,sizeof(body));
   }
  }
 }
 static const char*headers[]={"x-request-id","request-id","x-ms-request-id"};
 for(unsigned i=0;i<3&&!requestId[0];i++){
  const char*value=0;char bounded[80]={0};
  if(nativeHttpApi.header(call,headers[i],&value)>=0&&nativeHttpCopy(bounded,sizeof(bounded),value))
   dcDiagRequestId(bounded,len(bounded),requestId);
 }
 char row[768]={0};append(row,sizeof(row),"diag v=1 layer=http event=result source=native-http");
 diagNumber(row,sizeof(row)," id=",id);append(row,sizeof(row)," host=");append(row,sizeof(row),host);
 append(row,sizeof(row)," operation=");append(row,sizeof(row),operation);
 append(row,sizeof(row)," method=");append(row,sizeof(row),dcDiagMethod(methodCopy));
 if(statusHr>=0&&status<=599)diagNumber(row,sizeof(row)," http=",status);
 diagHex(row,sizeof(row),hr);
 if(networkHr>=0){
  /* diagNumber accepts unsigned only; retain the 32-bit platform bit pattern. */
  append(row,sizeof(row)," error_code=");
  if(platform>0x7fffffffU){append(row,sizeof(row),"-");diagNumber(row,sizeof(row),"",0x100000000ULL-platform);}
  else diagNumber(row,sizeof(row),"",platform);
 }
 append(row,sizeof(row)," error=");append(row,sizeof(row),error);
 append(row,sizeof(row)," response=");append(row,sizeof(row),response);
 append(row,sizeof(row)," request_id=");append(row,sizeof(row),requestId[0]?requestId:"absent");
 if(tracked)diagNumber(row,sizeof(row)," retry=",retry);
 append(row,sizeof(row)," correlation=exact");diagWrite(row);
 memset(urlCopy,0,sizeof(urlCopy));
}
static DWORD nativeHttpRegisterWorker(void*unused){
 (void)unused;
 /* Registration was claimed before scheduling. Recheck recording on the
  * worker: turning recording off before dispatch must not touch the library. */
 AcquireSRWLockExclusive(&nativeHttpLock);
 if(!dcLogging()){
  nativeHttpRegistering=0;nativeHttpCoverageRow(0,0);
  ReleaseSRWLockExclusive(&nativeHttpLock);return 0;
 }
 ReleaseSRWLockExclusive(&nativeHttpLock);
 /* Never load another instance or initialize the game's library ourselves. */
 H module=0;unsigned state=2;int hr=(int)0x8007007eU;
 struct NativeHttpApi api={0};
 if(nativeHttpPin(1,"libHttpClient.GDK.dll",&module)){
  /* Exact public symbol names and exact signatures; no ordinal fallbacks. */
  api.add=(int(NHTTP_CALL *)(NativeHttpRouted,void*))GetProcAddress(module,"HCAddCallRoutedHandler");
  api.id=(U64(NHTTP_CALL *)(void*))GetProcAddress(module,"HCHttpCallGetId");
  api.url=(int(NHTTP_CALL *)(void*,const char**,const char**))GetProcAddress(module,"HCHttpCallRequestGetUrl");
  api.status=(int(NHTTP_CALL *)(void*,unsigned*))GetProcAddress(module,"HCHttpCallResponseGetStatusCode");
  api.network=(int(NHTTP_CALL *)(void*,int*,unsigned*))GetProcAddress(module,"HCHttpCallResponseGetNetworkErrorCode");
  api.bodySize=(int(NHTTP_CALL *)(void*,U64*))GetProcAddress(module,"HCHttpCallResponseGetResponseBodyBytesSize");
  api.bodyBytes=(int(NHTTP_CALL *)(void*,U64,unsigned char*,U64*))GetProcAddress(module,"HCHttpCallResponseGetResponseBodyBytes");
  api.header=(int(NHTTP_CALL *)(void*,const char*,const char**))GetProcAddress(module,"HCHttpCallResponseGetHeader");
  state=3;hr=(int)0x8007007fU;
  if(api.add&&api.id&&api.url&&api.status&&api.network&&api.bodySize&&api.bodyBytes&&api.header){
   /* Forwarded exports may reside outside the named target. Pin every code
    * owner as well; a failure means no callbacks or getters may be invoked. */
   H owner=0;
   if(!nativeHttpPin(5,(const char*)api.add,&owner)||!nativeHttpPin(5,(const char*)api.id,&owner)||
      !nativeHttpPin(5,(const char*)api.url,&owner)||!nativeHttpPin(5,(const char*)api.status,&owner)||
      !nativeHttpPin(5,(const char*)api.network,&owner)||!nativeHttpPin(5,(const char*)api.bodySize,&owner)||
      !nativeHttpPin(5,(const char*)api.bodyBytes,&owner)||!nativeHttpPin(5,(const char*)api.header,&owner)){
    state=4;hr=(int)0x80004005U;goto finished;
   }
   /* Publish before registration: another thread may receive the callback
    * before add returns. Do not hold our lock across library calls. */
   nativeHttpApi.add=api.add;nativeHttpApi.id=api.id;
   nativeHttpApi.url=api.url;nativeHttpApi.status=api.status;
   nativeHttpApi.network=api.network;nativeHttpApi.bodySize=api.bodySize;
   nativeHttpApi.bodyBytes=api.bodyBytes;nativeHttpApi.header=api.header;
   int handler=api.add(nativeHttpResult,0);
   state=handler<0?4:1;hr=handler<0?(handler==-1?(int)0x80004005U:handler):0;
  }
 }
finished:
 AcquireSRWLockExclusive(&nativeHttpLock);
 nativeHttpRegistrationSucceeded=state==1;nativeHttpRegistering=0;nativeHttpCoverageRow(state,hr);
 ReleaseSRWLockExclusive(&nativeHttpLock);
 return 0;
}
static void nativeHttpObserve(void){
 AcquireSRWLockExclusive(&nativeHttpLock);
 if(!dcLogging()){
  /* diagWrite gates output. Re-enable will re-emit active coverage. */
  nativeHttpCoverageRow(0,0);ReleaseSRWLockExclusive(&nativeHttpLock);return;
 }
 if(nativeHttpRegistrationSucceeded){nativeHttpCoverageRow(1,0);ReleaseSRWLockExclusive(&nativeHttpLock);return;}
 if(nativeHttpRegistering){nativeHttpCoverageRow(5,0);ReleaseSRWLockExclusive(&nativeHttpLock);return;}
 nativeHttpRegistering=1;nativeHttpCoverageRow(5,0);ReleaseSRWLockExclusive(&nativeHttpLock);
 /* Pin our callback/worker code BEFORE scheduling, while this call still has
  * its caller-owned module lifetime. DllCanUnloadNow also sees the claim. */
 H owner=0;
 if(!nativeHttpPin(5,(const char*)&nativeHttpLock,&owner)){
  AcquireSRWLockExclusive(&nativeHttpLock);nativeHttpRegistering=0;
  nativeHttpCoverageRow(4,(int)0x80004005U);ReleaseSRWLockExclusive(&nativeHttpLock);return;
 }
 AcquireSRWLockExclusive(&nativeHttpLock);nativeHttpSelfPinned=1;ReleaseSRWLockExclusive(&nativeHttpLock);
 /* No lock or wait across scheduling. The worker can block on libHttpClient's
  * singleton lock while its owner continues initialization on the caller.
  * CloseHandle releases only our thread handle; it does not join the worker. */
 H thread=CreateThread(0,0,nativeHttpRegisterWorker,0,0,0);
 if(thread)CloseHandle(thread);
 else{
  AcquireSRWLockExclusive(&nativeHttpLock);nativeHttpRegistering=0;
  nativeHttpCoverageRow(4,(int)0x80004005U);ReleaseSRWLockExclusive(&nativeHttpLock);
 }
 /* Failed discovery/registration is retried on later observe calls; successful
  * registration is once per process. Library teardown/reinit is not inferred. */
}
#undef NHTTP_CALL
