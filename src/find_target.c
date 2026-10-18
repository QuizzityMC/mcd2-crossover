typedef unsigned long D; typedef long L; typedef unsigned long long U; typedef void* H;
#define I __declspec(dllimport)
I H GetStdHandle(D);I int WriteFile(H,const void*,D,D*,void*);I void ExitProcess(D);
I H OpenProcess(D,int,D);I int CloseHandle(H);I D GetLastError(void);
I H CreateToolhelp32Snapshot(D,D);
#include "target_identity.h"
typedef struct {D size,usage,pid;U heap;D module,threads,parent;L priority;D flags;W exe[260];} PE;
I int Process32FirstW(H,PE*);I int Process32NextW(H,PE*);
static H output;
static void text(const char*s){D n=0,w;while(s[n])n++;WriteFile(output,s,n,&w,0);}
static void num(U v){char b[24];D n=0,w;do{b[n++]=(char)('0'+v%10);v/=10;}while(v);
    for(D i=0;i<n/2;i++){char c=b[i];b[i]=b[n-1-i];b[n-1-i]=c;}WriteFile(output,b,n,&w,0);}
static int equal_name(const W*a,const char*b){for(;*a&&*b;a++,b++){D x=*a,y=(unsigned char)*b;if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return 0;}return !*a&&!*b;}
static const char* role(const W*name){const char* known[]={"Dungeons-Win64-Shipping.exe","Dungeons-WinGDK-Shipping.exe","CrashReportClient.exe","winedbg.exe","WerFault.exe","steam.exe","steamwebhelper.exe","UnrealCEFSubProcess.exe","crashpad_handler.exe"};for(D i=0;i<sizeof(known)/sizeof(known[0]);i++)if(equal_name(name,known[i]))return known[i];return "[other-process]";}
void mainCRTStartup(void){
    output=GetStdHandle((D)-11);
    if(!prepare_expected()){text("{\"error\":\"expected_image_unreadable\"}\n");ExitProcess(2);}
    H snap=CreateToolhelp32Snapshot(2,0);
    if(snap==(H)(U)-1){text("{\"error\":\"process_list_failed\"}\n");ExitProcess(3);}
    PE p;p.size=sizeof(p);D count=0,pid=0,unreadable=0;U created=0;
    int more=Process32FirstW(snap,&p);
    if(!more){CloseHandle(snap);text("{\"error\":\"process_list_empty_or_failed\"}\n");ExitProcess(3);}
    text("{\"processes\":[");D visited=0;while(more && visited<512){if(visited++)text(",");text("{\"pid\":");num(p.pid);text(",\"parent_pid\":");num(p.parent);text(",\"threads\":");num(p.threads);text(",\"role\":\"");text(role(p.exe));text("\"}");H process=OpenProcess(0x1000,0,p.pid);
        if(process){int match=matching_image(process);if(match==1){
            count++;pid=p.pid;created=process_created(process);
        }else if(match<0)unreadable++;CloseHandle(process);}else unreadable++;
        p.size=sizeof(p);more=Process32NextW(snap,&p);
    }
    D enumeration_error=GetLastError();CloseHandle(snap);
    if(more || enumeration_error!=18){text("],\"error\":\"process_list_incomplete\"}\n");ExitProcess(3);}
    text("],\"matched_count\":");num(count);text(",\"unreadable_processes\":");num(unreadable);
    if(count==1&&created){text(",\"windows_pid\":");num(pid);text(",\"creation_time\":");num(created);}
    text("}\n");ExitProcess(count==1&&created?0:4);
}
