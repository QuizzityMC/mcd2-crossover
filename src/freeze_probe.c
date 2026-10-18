typedef unsigned long D; typedef long L; typedef unsigned long long U; typedef void* H;
#define I __declspec(dllimport)
I H GetStdHandle(D); I int WriteFile(H,const void*,D,D*,void*); I void ExitProcess(D);
I char* GetCommandLineA(void); I H OpenProcess(D,int,D); I H OpenThread(D,int,D); I int CloseHandle(H);
I int CheckRemoteDebuggerPresent(H,int*); I D GetLastError(void); I H CreateToolhelp32Snapshot(D,D);
typedef struct {D size,usage,tid,pid;L base,delta;D flags;} TE;
I int Thread32First(H,TE*); I int Thread32Next(H,TE*); I L NtQueryInformationThread(H,D,void*,D,D*);
I int GetThreadContext(H,void*);
#include "target_identity.h"
typedef struct {D size,id,pid,global_usage,process_usage;unsigned char*base;D image_size;H module;char name[256];char path[260];} ME;
I int Module32First(H,ME*);I int Module32Next(H,ME*);
static struct {U base;D size;D kind;} modules[512];static D module_count;
static int eq(const char*a,const char*b){while(*a&&*a==*b){a++;b++;}return *a==*b;}
static const char* names[]={"[other-module]","ntdll.dll","kernel32.dll","kernelbase.dll","Dungeons-Win64-Shipping.exe","Dungeons-WinGDK-Shipping.exe","steamclient64.dll","GameOverlayRenderer64.dll","libcef.dll","chrome_elf.dll","dbghelp.dll","xgameruntime.dll","xgameruntime-native.dll","XCurl.dll"};
static void load_modules(D pid){H s=CreateToolhelp32Snapshot(0x18,pid);ME e;e.size=sizeof(e);int ok=Module32First(s,&e);while(ok&&module_count<512){D k=0;for(D i=1;i<sizeof(names)/sizeof(names[0]);i++)if(eq(e.name,names[i]))k=i;modules[module_count].base=(U)e.base;modules[module_count].size=e.image_size;modules[module_count++].kind=k;e.size=sizeof(e);ok=Module32Next(s,&e);}CloseHandle(s);}
typedef struct {U offset; unsigned short segment; D mode;} ADDRESS64;
typedef struct {U thread;D callback_stack,callback_bstore,next_callback,frame_pointer;U ki_call_user,ke_user_callback,system_start,ki_user_exception,stack_base,stack_limit;D build,retpoline_table_size;U retpoline_table;D retpoline_offset,retpoline_size;U reserved[2];} KDHELP64;
typedef struct {ADDRESS64 pc,ret,frame,stack,bstore;void*function;U params[4];int far,virt;U reserved[3];KDHELP64 help;} STACKFRAME64;
I D SymSetOptions(D);I int SymInitialize(H,const char*,int);I int SymCleanup(H);
I void* SymFunctionTableAccess64(H,U);I U SymGetModuleBase64(H,U);
I int StackWalk64(D,H,H,STACKFRAME64*,void*,void*,void*(*)(H,U),U(*)(H,U),void*);
static int symbols_ok;
static H output;
static void phase(const char*name,D tid);
static void text(const char*s){D n=0,w;while(s[n])n++;WriteFile(output,s,n,&w,0);}
static void num(U v){char b[24];D n=0,w;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);for(D i=0;i<n/2;i++){char c=b[i];b[i]=b[n-1-i];b[n-1-i]=c;}WriteFile(output,b,n,&w,0);}
static void phase(const char*name,D tid){H save=output;output=GetStdHandle((D)-12);text("{\"phase\":\"");text(name);text("\",\"tid\":");num(tid);text("}\n");output=save;}
static void key(const char*k,U v){text(k);num(v);}
static void location(U address){for(D i=0;i<module_count;i++)if(address>=modules[i].base&&address-modules[i].base<modules[i].size){text(",\"start_module\":\"");text(names[modules[i].kind]);text("\"");key(",\"start_rva\":",address-modules[i].base);return;}}
static void stackwalk(H process,H thread,unsigned char*c){
STACKFRAME64 f;unsigned char*z=(unsigned char*)&f;for(D i=0;i<sizeof(f);i++)z[i]=0;
f.pc.offset=*(U*)(c+248);f.frame.offset=*(U*)(c+160);f.stack.offset=*(U*)(c+152);f.pc.mode=f.frame.mode=f.stack.mode=3;
text(",\"windows_stack\":[");U lastpc=0,lastsp=0;
for(D i=0;i<32;i++){int ok=StackWalk64(0x8664,process,thread,&f,c,0,SymFunctionTableAccess64,SymGetModuleBase64,0);if(!ok||!f.pc.offset||(lastpc==f.pc.offset&&lastsp==f.stack.offset))break;if(i)text(",");text("{\"pc\":");num(f.pc.offset);location(f.pc.offset);text("}");lastpc=f.pc.offset;lastsp=f.stack.offset;}
text("]");}
void mainCRTStartup(void){output=GetStdHandle((D)-11);phase("started",0);char*cmd=GetCommandLineA();D pid=0;
/* Last argument is a decimal Windows PID. No path or account data is emitted. */
for(char*p=cmd;*p;p++)if(*p==' '){D n=0;char*q=p+1;while(*q>='0'&&*q<='9'){n=n*10+*q-'0';q++;}if(n&&!*q)pid=n;}
if(!pid){text("{\"error\":\"pid_required\"}\n");ExitProcess(2);}
phase("open_process",0);H process=OpenProcess(0x410,0,pid);if(!process){text("{\"error\":\"open_process\",\"code\":");num(GetLastError());text("}\n");ExitProcess(3);}
U created=process_created(process),expected=expected_created();
if(!prepare_expected()||matching_image(process)!=1||!expected||created!=expected){CloseHandle(process);text("{\"error\":\"target_identity_changed\"}\n");ExitProcess(4);}
phase("modules",0);load_modules(pid);
#ifdef CAPTURE_CONTEXT
phase("symbols",0);SymSetOptions(0x81004);symbols_ok=SymInitialize(process,"",1);
#endif
phase("debugger_state",0);int debug=0,ok=CheckRemoteDebuggerPresent(process,&debug);text("{\"identity_verified\":1,\"windows_pid\":");num(pid);key(",\"creation_time\":",created);text(",\"debug_query_ok\":");num(ok!=0);if(!ok)key(",\"debug_query_error\":",GetLastError());key(",\"debugger_present\":",debug!=0);key(",\"symbols_ok\":",symbols_ok!=0);text(",\"threads\":[");
phase("thread_list",0);H snap=CreateToolhelp32Snapshot(4,0);TE e={sizeof(TE),0,0,0,0,0,0};int more=Thread32First(snap,&e),first=1;
D visited=0;while(more && visited++<4096){if(e.pid==pid){if(!first)text(",");first=0;text("{\"tid\":");num(e.tid);phase("thread_metadata",e.tid);H t=OpenThread(0x48,0,e.tid);
if(t){D count=0;U start=0;L status=NtQueryInformationThread(t,35,&count,sizeof(count),0);key(",\"suspend_status\":",(D)status);if(status==0)key(",\"suspend_count\":",count);
status=NtQueryInformationThread(t,9,&start,sizeof(start),0);key(",\"start_status\":",(D)status);if(status==0){key(",\"start_address\":",start);location(start);}
/* On-demand capture: GetThreadContext can trigger a temporary Wine SIGUSR1 stop. */
#ifdef CAPTURE_CONTEXT
phase("thread_context",e.tid);if(1){__declspec(align(16)) unsigned char c[1232];for(D i=0;i<sizeof(c);i++)c[i]=0;*(D*)(c+48)=0x100003;int got=GetThreadContext(t,c);key(",\"context_ok\":",got!=0);if(!got)key(",\"context_error\":",GetLastError());if(got){key(",\"rip\":",*(U*)(c+248));key(",\"rsp\":",*(U*)(c+152));if(symbols_ok){phase("thread_stack",e.tid);stackwalk(process,t,c);}}}
#endif
phase("thread_complete",e.tid);
CloseHandle(t);}else key(",\"open_error\":",GetLastError());text("}");}e.size=sizeof(e);more=Thread32Next(snap,&e);}
D enum_error=GetLastError();text("]");if(more || enum_error!=18)key(",\"thread_list_error\":",more?234:enum_error);text("}\n");CloseHandle(snap);if(symbols_ok)SymCleanup(process);CloseHandle(process);phase("complete",0);ExitProcess(0);}
