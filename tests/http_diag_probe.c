/* Native execution of production wrappers; no network or Windows DLL needed. */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define DC_HTTP_NATIVE_TEST 1
typedef unsigned long DWORD;
typedef void *HANDLE;
static HANDLE self;
static int waitqueueFix;
static char trustedCA[2048];
static void setupCA(void) {}
static int waitqueue_fix_apply(void) { return 0; }
static unsigned long long GetTickCount64(void) { static unsigned long long t; return ++t; }
static DWORD GetCurrentProcessId(void) { return 123; }
static int recording=1;
static int dcLogging(void) { return recording; }
static char logs[65536];
static void logline(const char*s) { if(recording){assert(strlen(logs)+strlen(s)<sizeof(logs));strcat(logs,s);} }
static void *fn(const char *);
#include "../src/curl.c"
void AcquireSRWLockExclusive(LOCK*p) {(void)p;}
void ReleaseSRWLockExclusive(LOCK*p) {(void)p;}
struct Easy {
 DEBUGFN debug; void *debugdata; WRITEFN write; void *writedata;
 int verbose; long status; const char *body,*url,*requestHeader;
 long long postSize,uploadSize,performedPostSize,performedUploadSize; int defaults,delivered,dataSets;
};
static struct Easy pool[16];static int used,addError,removeError,setError;
static SIZE sink(char*p,SIZE s,SIZE n,void*d){(void)p;*(int*)d+=(int)(s*n);return s*n;}
static int fakeSet(void*e,int o,...){
 struct Easy*t=e;va_list a;va_start(a,o);
 if(setError){va_end(a);return 43;}
 if(o==30120)t->postSize=va_arg(a,long long);
 else if(o==30115)t->uploadSize=va_arg(a,long long);
 else {void*v=va_arg(a,void*);switch(o){
 case 20094:t->debug=(DEBUGFN)v;break;case 10095:t->debugdata=v;break;
 case 20011:t->write=(WRITEFN)v;break;case 10001:t->writedata=v;t->dataSets++;break;
 case 41:t->verbose=(int)(uintptr_t)v;break;case 10002:t->url=v;break;
 }}va_end(a);return 0;
}
static int fakeGet(void*e,int o,...){struct Easy*t=e;va_list a;va_start(a,o);if(o==0x200002)*va_arg(a,long*)=t->status;else if(o==0x100001)*va_arg(a,char**)=(char*)t->url;va_end(a);return 0;}
static int fakePerform(void*e){
 struct Easy*t=e;t->performedPostSize=t->postSize;t->performedUploadSize=t->uploadSize;char *header="HTTP/1.1 401 Unauthorized\r\n";
 if(t->verbose&&t->debug){t->debug(e,1,header,strlen(header),t->debugdata);if(t->requestHeader)t->debug(e,1,(char*)t->requestHeader,strlen(t->requestHeader),t->debugdata);}
 if(t->body){SIZE n=strlen(t->body);if(t->write){assert(t->write((char*)t->body,1,n,t->writedata)==n);}else t->defaults++;}
 return 0;
}
static void *fakeInit(void){assert(used<16);return &pool[used++];}
static void fakeReset(void*e){memset(e,0,sizeof(struct Easy));}
static void fakeCleanup(void*e){(void)e;}
static void *fakeDup(void*e){void*r=fakeInit();memcpy(r,e,sizeof(struct Easy));return r;}
static int fakeAdd(void*m,void*e){(void)m;(void)e;return addError;}
static int fakeRemove(void*m,void*e){(void)m;(void)e;return removeError;}
static struct Msg message;static int pending;
static struct Msg *fakeInfo(void*m,int*r){(void)m;*r=0;if(pending){pending=0;return &message;}return 0;}
static int debugCalls;
static int userDebug(void*e,int k,char*p,SIZE n,void*d){(void)e;(void)k;(void)p;(void)n;assert(d==&debugCalls);debugCalls++;return 0;}
static int fakeGlobal(long x){(void)x;return 0;}
static void *fn(const char*n){
 if(!strcmp(n,"curl_easy_setopt"))return fakeSet;
 if(!strcmp(n,"curl_easy_getinfo"))return fakeGet;
 if(!strcmp(n,"curl_easy_perform"))return fakePerform;
 if(!strcmp(n,"curl_easy_init"))return fakeInit;
 if(!strcmp(n,"curl_easy_reset"))return fakeReset;
 if(!strcmp(n,"curl_easy_cleanup"))return fakeCleanup;
 if(!strcmp(n,"curl_easy_duphandle"))return fakeDup;
 if(!strcmp(n,"curl_multi_add_handle"))return fakeAdd;
 if(!strcmp(n,"curl_multi_remove_handle"))return fakeRemove;
 if(!strcmp(n,"curl_multi_info_read"))return fakeInfo;
 if(!strcmp(n,"curl_global_init"))return fakeGlobal;
 assert(!"unexpected symbol");return 0;
}
static void clearLog(void){logs[0]=0;}
static void has(const char*s){if(!strstr(logs,s)){fprintf(stderr,"missing: %s\n%s",s,logs);assert(0);}}
static void lacks(const char*s){assert(!strstr(logs,s));}
static int count(const char*s){int n=0;const char*p=logs;while((p=strstr(p,s))){n++;p+=strlen(s);}return n;}
static void pair(void){
 const char*a=strstr(logs,"event=start id="),*b=strstr(logs,"event=complete id=");unsigned long long x=0,y=0;
 assert(a&&b);assert(sscanf(a,"event=start id=%llu",&x)==1);assert(sscanf(b,"event=complete id=%llu",&y)==1);assert(x&&x==y);
}
static int emitFixture(void){
 struct Easy*e=curl_easy_init();int bytes=0;
 curl_easy_setopt(e,10002,"https://profile.xboxlive.com/users/ACCOUNT_SENTINEL/profile?token=QUERY_SENTINEL");
 curl_easy_setopt(e,20011,(void*)sink);curl_easy_setopt(e,10001,&bytes);curl_easy_setopt(e,47,(void*)1);
 e->status=401;e->body="{\"error\":\"InvalidToken\",\"token\":\"TOKEN_SENTINEL\",\"account\":\"ACCOUNT_SENTINEL\",\"html\":\"<b>HTML_SENTINEL</b>\"}";
 e->requestHeader="X-Request-Id: 12345678-1234-1234-1234-123456789abc\r\n";
 clearLog();curl_easy_perform(e);pair();has("error=InvalidToken response=json");
 has("request_id=12345678-1234-1234-1234-123456789abc");lacks("SENTINEL");
 // Print the production emitter's exact rows, not a re-created test schema.
 fputs(logs,stdout);
 e->body="<html><title>Bad Request</title><body>HTML_SENTINEL TOKEN_SENTINEL ACCOUNT_SENTINEL</body></html>";
 clearLog();curl_easy_perform(e);pair();has("error=BadRequest response=markup");lacks("SENTINEL");fputs(logs,stdout);
 curl_easy_cleanup(e);return 0;
}
int main(int argc,char**argv){
 if(argc==2&&!strcmp(argv[1],"--emit-fixture"))return emitFixture();
 assert(argc==1);
 struct Easy*e=curl_easy_init();int bytes=0;
 curl_easy_setopt(e,10002,"https://profile.xboxlive.com/");e->body="default output";e->status=200;
 curl_easy_perform(e);assert(e->defaults==1);assert(e->dataSets==0);e->defaults=0;
 curl_easy_setopt(e,10002,"https://83156.playfabapi.com/Client/LoginWithSteam?token=QUERY_SECRET");
 curl_easy_setopt(e,20011,(void*)sink);curl_easy_setopt(e,10001,&bytes);curl_easy_setopt(e,47,(void*)1);
 e->status=401;e->body="{\"error\":\"InvalidSteamTicket\",\"token\":\"BODY_SECRET\"}";
 e->requestHeader="X-Request-Id: 12345678-1234-1234-1234-123456789abc\r\n";
 clearLog();curl_easy_perform(e);pair();has("diag v=1 source=curl layer=http");has("pid=123 retry=0 correlation=exact");has("operation=playfab-login-steam method=POST http=401 curl=0");has("error=InvalidSteamTicket response=json");has("request_id=12345678-1234-1234-1234-123456789abc");lacks("QUERY_SECRET");lacks("BODY_SECRET");assert(bytes==(int)strlen(e->body));assert(!trace(e,0)->diagnosticId);assert(!trace(e,0)->incoming[0]);
 unsigned long long sequence=requestSequence;
 e->body="<html><body>alice private identity InvalidSteamTicket</body></html>";e->requestHeader="X-Request-Id: alice-secret\r\n";
 clearLog();curl_easy_perform(e);pair();assert(requestSequence>sequence);has("error=other response=markup request_id=absent");lacks("alice");lacks("InvalidSteamTicket");
 e->body="<html><title>400 Bad Request</title><body>HTML_SECRET</body></html>";
 clearLog();curl_easy_perform(e);has("error=BadRequest response=markup");lacks("HTML_SECRET");
 clearLog();headerMetadata(trace(e,0),"X-ACCOUNT_SENTINEL: TOKEN_SENTINEL",32,"source");has("name=other nameValid=1");lacks("SENTINEL");
 clearLog();headerMetadata(trace(e,0),"CoNtEnT-LeNgTh: 123",18,"wire");has("name=content-length nameValid=1");
 e->status=200;e->body="{\"error\":\"InvalidSteamTicket\",\"private\":\"SUCCESS_SECRET\"}";
 clearLog();curl_easy_perform(e);has("error=none response=json");lacks("InvalidSteamTicket");lacks("SUCCESS_SECRET");
 curl_easy_setopt(e,10002,"https://profile.xboxlive.com/users/PRIVATE_ID/profile?token=QUERY_SECRET");e->status=401;
 clearLog();curl_easy_perform(e);has("host=profile.xboxlive.com operation=profile");lacks("PRIVATE_ID");lacks("QUERY_SECRET");
 curl_easy_setopt(e,10002,"https://PRIVATE_HOST.invalid/users/PRIVATE_ID");
 clearLog();curl_easy_perform(e);has("host=other operation=other");has("response=unobserved");lacks("PRIVATE_HOST");lacks("PRIVATE_ID");
 // Recording begins after URL setup: callbacks must be installed at perform.
 recording=0;curl_easy_setopt(e,10002,"https://profile.xboxlive.com/secret");assert(e->write==sink);
 recording=1;clearLog();curl_easy_perform(e);pair();has("response=json");assert(e->write==diagnosticWrite);
 // Redirect headers re-evaluate the effective endpoint before body capture.
 clearLog();requestTiming(e,0,0,0);e->url="https://unknown.invalid/REDIRECT_SECRET";
 char redirected[]="HTTP/1.1 401 Unauthorized\r\n";
 diagnosticDebug(e,1,redirected,strlen(redirected),trace(e,0));
 diagnosticWrite((char*)e->body,1,strlen(e->body),trace(e,0));assert(!trace(e,0)->inlen);
 result(e,0);pair();has("host=other operation=other");has("response=unobserved");lacks("REDIRECT_SECRET");
 curl_easy_setopt(e,10002,"https://profile.xboxlive.com/");requestSequence=4294967295ULL;
 clearLog();curl_easy_perform(e);pair();has("id=4294967296");
 // Caller debug callbacks retain their own userdata and verbosity semantics.
 curl_easy_setopt(e,20094,(void*)userDebug);curl_easy_setopt(e,10095,&debugCalls);curl_easy_setopt(e,41,(void*)1);
 curl_easy_perform(e);assert(debugCalls>0);
 curl_easy_setopt(e,41,0);int before=debugCalls;curl_easy_perform(e);assert(debugCalls==before);
 // Unknown error strings, long bodies and injected methods cannot escape.
 e->body="{\"error\":\"PRIVATE_ERROR_TOKEN\"}";clearLog();curl_easy_perform(e);has("error=other response=json");lacks("PRIVATE_ERROR_TOKEN");
 char large[9000];memset(large,' ',sizeof(large));memcpy(large,"{\"error\":\"InvalidSteamTicket\"}",30);large[sizeof(large)-1]=0;e->body=large;
 clearLog();curl_easy_perform(e);has("error=other response=json");lacks("InvalidSteamTicket");
 curl_easy_setopt(e,10036,"POST\r\nPRIVATE_METHOD");e->body="";clearLog();curl_easy_perform(e);has("method=other");has("response=empty");lacks("PRIVATE_METHOD");curl_easy_setopt(e,10036,0);
 e->body="{\"error\":\"InvalidSteamTicket\"}";
 // Duplication must point at its own trace, while preserving the caller's sink.
 struct Easy*d=curl_easy_duphandle(e);assert(d->writedata==trace(d,0));clearLog();curl_easy_perform(d);pair();assert(trace(d,0)->write==sink);
 // Clearing a callback must restore libcurl's default, never a swallowing wrapper.
 curl_easy_setopt(e,20011,0);assert(!e->write);assert(e->writedata==&bytes);clearLog();curl_easy_perform(e);assert(e->defaults==1);has("response=unobserved");
 // Reset follows libcurl semantics: options and caller callbacks are cleared.
 curl_easy_reset(d);assert(!trace(d,0)->write);assert(!d->write);curl_easy_setopt(d,10002,"https://profile.xboxlive.com/");d->body="default output";d->status=200;clearLog();curl_easy_perform(d);assert(d->defaults==1);has("method=GET");
 // Failed setopt must not poison saved callback state.
 setError=1;assert(curl_easy_setopt(e,20011,(void*)sink)==43);setError=0;assert(!trace(e,0)->write);
 // Multi completion keeps correlation; failed add completes exactly once.
 clearLog();assert(!curl_multi_add_handle(0,e));unsigned long long activeId=trace(e,0)->diagnosticId;
 addError=7;assert(curl_multi_add_handle(0,e)==7);assert(trace(e,0)->diagnosticId==activeId);assert(count("event=start")==1);addError=0;fakePerform(e);message.type=1;message.easy=e;message.data.code=0;pending=1;int remaining;curl_multi_info_read(0,&remaining);pair();assert(count("event=complete")==1);
 // Removal of an already completed handle does not duplicate the row.
 assert(!curl_multi_remove_handle(0,e));assert(count("event=complete")==1);
 // Failed removal preserves correlation, callbacks, and framing override.
 struct Header pendingLength={"Content-Length: 17",0};curl_easy_setopt(e,10023,&pendingLength);
 clearLog();curl_multi_add_handle(0,e);activeId=trace(e,0)->diagnosticId;removeError=2;
 assert(curl_multi_remove_handle(0,e)==2);assert(trace(e,0)->diagnosticId==activeId);assert(trace(e,0)->sizeOverrideApplied);assert(!count("event=complete"));
 removeError=0;assert(!curl_multi_remove_handle(0,e));pair();has("curl=42");assert(!trace(e,0)->diagnosticId);assert(!trace(e,0)->sizeOverrideApplied);assert(e->postSize==-1);
 assert(!curl_multi_remove_handle(0,e));assert(count("event=complete")==1);curl_easy_setopt(e,10023,0);
 clearLog();addError=7;assert(curl_multi_add_handle(0,e)==7);pair();has("http=0 curl=7");assert(!trace(e,0)->diagnosticId);addError=0;
 clearLog();curl_multi_add_handle(0,e);curl_easy_cleanup(e);pair();has("curl=42");assert(!trace(e,0));
 // Framing repair and restoration must remain unchanged.
 struct Header h={"Content-Length: 123",0};curl_easy_setopt(d,10023,&h);clearLog();curl_easy_perform(d);assert(d->performedPostSize==123);assert(d->postSize==-1);assert(!trace(d,0)->sizeOverrideApplied);
 curl_easy_setopt(d,46,(void*)1);curl_easy_perform(d);assert(d->performedUploadSize==123);assert(d->uploadSize==-1);
 struct Header duplicate={"Content-Length: 123",&h};curl_easy_setopt(d,10023,&duplicate);curl_easy_perform(d);assert(d->performedUploadSize==-1);
 struct Header transfer={"Transfer-Encoding: chunked",&h};curl_easy_setopt(d,10023,&transfer);curl_easy_perform(d);assert(d->performedUploadSize==-1);
 struct Header invalid={"Content-Length: 9223372036854775808",0};curl_easy_setopt(d,10023,&invalid);curl_easy_perform(d);assert(d->performedUploadSize==-1);
 // Reset of an active multi handle emits a single cancellation completion.
 clearLog();curl_multi_add_handle(0,d);curl_easy_reset(d);pair();has("curl=42");assert(!trace(d,0)->diagnosticId);
 // Verification-reducing options are still rejected.
 assert(curl_easy_setopt(d,64,0)==4);assert(curl_easy_setopt(d,81,(void*)1)==4);
 puts("http diagnostics native: ok");return 0;
}
