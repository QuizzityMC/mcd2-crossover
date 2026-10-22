#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../src/diagnostic.inc"
int main(void){
 char host[96],operation[48],error[64],id[37];
 dcDiagRoute("https://profile.xboxlive.com/users/xuid(SYNTHETIC_ACCOUNT)/profile?token=SYNTHETIC_SECRET",host,operation);
 assert(!strcmp(host,"profile.xboxlive.com")&&!strcmp(operation,"profile"));
 const char*bad[]={"http://profile.xboxlive.com/","https://profile.xboxlive.com.evil.invalid/","https://SYNTHETIC_SECRET.xboxlive.com/","https://secret@profile.xboxlive.com/","https://profile.xboxlive.com:444/","https://profile.xboxlive.com\\evil/","https://profile.xboxlive.com\r\nInjected/",NULL};
 for(unsigned i=0;i<sizeof(bad)/sizeof(*bad);i++){dcDiagRoute(bad[i],host,operation);assert(!strcmp(host,"other"));}
 dcDiagRoute("https://83156.playfabapi.com/Client/LoginWithSteam?ticket=SYNTHETIC_SECRET",host,operation);assert(!strcmp(operation,"playfab-login-steam"));
 dcDiagRoute("https://vex.minecraftservices.com/characters/SYNTHETIC_ACCOUNT",host,operation);assert(!strcmp(operation,"minecraft-service"));
 dcDiagRoute("https://PROFILE.XBOXLIVE.COM/path",host,operation);assert(!strcmp(host,"profile.xboxlive.com"));
 assert(!strcmp(dcDiagMethod("POST"),"POST"));assert(!strcmp(dcDiagMethod("POST token=secret"),"other"));
 dcDiagError("{\"error\":\"InvalidSignature\",\"access_token\":\"SYNTHETIC_SECRET\"}",error);assert(!strcmp(error,"InvalidSignature"));
 dcDiagError("{\"profile\":{\"error\":\"InvalidSignature\"},\"code\":\"Unauthorized\"}",error);assert(!strcmp(error,"Unauthorized"));
 dcDiagError("{\"error\":\"SYNTHETIC_SECRET\"}",error);assert(!strcmp(error,"other"));
 dcDiagError("{\"profile\":{\"error\":\"InvalidSignature\"}}",error);assert(!strcmp(error,"none"));
 dcDiagError("{\"error\":\"Unauthorized\\\"SYNTHETIC_SECRET\"}",error);assert(!strcmp(error,"other"));
 assert(dcDiagRequestId(" 00000000-0000-4000-8000-000000000001\r\n",39,id));
 assert(!strcmp(id,"00000000-0000-4000-8000-000000000001"));
 assert(!dcDiagRequestId("SYNTHETIC_SECRET",16,id)&&!id[0]);
 char input[512];unsigned seed=13;
 for(unsigned trial=0;trial<10000;trial++){
  unsigned n=trial%sizeof(input);for(unsigned i=0;i<n;i++){seed=seed*1664525U+1013904223U;input[i]=(char)(1+seed%126);}input[n]=0;
  dcDiagRoute(input,host,operation);dcDiagError(input,error);dcDiagRequestId(input,n,id);
  assert(strlen(host)<96&&strlen(operation)<48&&strlen(error)<64);
 }
 puts("diagnostic vocabulary: fixed public routes, errors, UUIDs and 10000 malformed inputs passed");
}
