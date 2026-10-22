/* Diagnostic vocabulary shared by the runtime and curl adapters.
 * No raw URL, request body, account identifier or arbitrary server text leaves
 * these helpers. Unknown values stay visible as 'other', not silently dropped. */
static int dcDiagEq(const char*a,const char*b){if(!a||!b)return 0;while(*a&&*a==*b){a++;b++;}return *a==*b;}
static void dcDiagCopy(char*out,unsigned cap,const char*in){unsigned n=0;while(in&&*in&&n+1<cap)out[n++]=*in++;out[n]=0;}
static const char* dcDiagMethod(const char*m){
 static const char*known[]={"GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"};
 for(unsigned i=0;i<7;i++)if(dcDiagEq(m,known[i]))return known[i];return "other";
}
static void dcDiagRoute(const char*url,char host[96],char operation[48]){
 dcDiagCopy(host,96,"other");dcDiagCopy(operation,48,"other");if(!url)return;
 const char*prefix="https://";while(*prefix)if(*url++!=*prefix++)return;
 char parsed[96]={0};unsigned n=0;
 while(*url&&*url!='/'&&*url!='?'&&*url!='#'){
  char c=*url++;if(c>='A'&&c<='Z')c+=32;
  if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='-')||n>=95)return;parsed[n++]=c;
 }
 static const struct {const char*host;const char*op;} known[]={
  {"profile.xboxlive.com","profile"},{"social.xboxlive.com","social"},
  {"peoplehub.xboxlive.com","social"},{"presence.xboxlive.com","presence"},
  {"userpresence.xboxlive.com","presence"},{"privacy.xboxlive.com","privacy"},
  {"achievements.xboxlive.com","achievements"},{"multiplayer.xboxlive.com","multiplayer"},
  {"sessiondirectory.xboxlive.com","multiplayer"},{"userstats.xboxlive.com","statistics"},
  {"statsread.xboxlive.com","statistics"},{"inventory.xboxlive.com","inventory"},
  {"xblmessaging.xboxlive.com","messaging"},{"licensing.xboxlive.com","licensing"},
  {"titlehub.xboxlive.com","xbox-other"},{"reputation.xboxlive.com","xbox-other"},
  {"device.auth.xboxlive.com","xbox-other"},{"user.auth.xboxlive.com","xbox-other"},
  {"xsts.auth.xboxlive.com","xbox-other"},{"api.minecraftservices.com","minecraft-service"},
  {"vex.minecraftservices.com","minecraft-service"},{"83156.playfabapi.com","playfab-other"}
 };
 for(unsigned i=0;i<sizeof(known)/sizeof(known[0]);i++)if(dcDiagEq(parsed,known[i].host)){
  dcDiagCopy(host,96,known[i].host);dcDiagCopy(operation,48,known[i].op);break;
 }
 if(dcDiagEq(host,"other"))return;
 /* Path is compared only against fixed public operations, never copied out. */
 char path[96]={0};n=0;while(*url&&*url!='?'&&*url!='#'&&n<95)path[n++]=*url++;
 if(*url&&*url!='?'&&*url!='#')return;
 if(dcDiagEq(host,"83156.playfabapi.com")){
  static const struct{const char*path;const char*op;} routes[]={
   {"/Client/LoginWithSteam","playfab-login-steam"},{"/Client/LoginWithXbox","playfab-login-xbox"},
   {"/Client/LinkXboxAccount","playfab-link-xbox"},{"/Authentication/GetEntityToken","playfab-entity-token"}};
  for(unsigned i=0;i<4;i++)if(dcDiagEq(path,routes[i].path))dcDiagCopy(operation,48,routes[i].op);
 }else if(dcDiagEq(path,"/authentication/login_with_xbox")||dcDiagEq(path,"/login"))dcDiagCopy(operation,48,"minecraft-login");
}
static int dcDiagRequestId(const char*p,unsigned long long n,char out[37]){
 out[0]=0;while(n&&(*p==' '||*p=='\t')){p++;n--;}
 while(n&&(p[n-1]=='\r'||p[n-1]=='\n'||p[n-1]==' '||p[n-1]=='\t'))n--;
 if(n!=36)return 0;
 for(unsigned i=0;i<36;i++){
  char c=p[i];if(i==8||i==13||i==18||i==23){if(c!='-')return 0;}
  else if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F')))return 0;
 }
 for(unsigned i=0;i<36;i++)out[i]=p[i];out[36]=0;return 1;
}
/* Match only an unescaped JSON root key. Nested profiles and tokens are never
 * treated as service errors. The caller supplies a bounded NUL-terminated body. */
static const char*dcDiagField(const char*b,const char*key){
 if(!b)return 0;int depth=0,inString=0,escape=0;
 for(const char*p=b;*p;p++){
  if(inString){if(escape){escape=0;continue;}if(*p=='\\'){escape=1;continue;}if(*p=='"')inString=0;continue;}
  if(*p=='{'||*p=='['){depth++;continue;}if(*p=='}'||*p==']'){depth--;continue;}
  if(*p=='"'){
   if(depth==1){const char*q=p+1,*k=key;while(*k&&*q==*k){q++;k++;}
    if(!*k&&*q=='"'){q++;while(*q==' '||*q=='\n'||*q=='\r'||*q=='\t')q++;if(*q==':'){q++;while(*q==' '||*q=='\n'||*q=='\r'||*q=='\t')q++;return q;}}}
   inString=1;
  }
 }return 0;
}
static void dcDiagError(const char*body,char out[64]){
 dcDiagCopy(out,64,"none");const char*p=dcDiagField(body,"error");if(!p)p=dcDiagField(body,"code");if(!p)return;
 dcDiagCopy(out,64,"other");if(*p++!='"')return;char word[64]={0};unsigned n=0;
 while(*p&&*p!='"'&&n<63){char c=*p++;if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'))return;word[n++]=c;}
 if(*p!='"')return;
 static const char*known[]={"InvalidSteamTicket","AccountNotFound","SteamNotEnabledForTitle",
  "InvalidContentType","InvalidParams","InvalidRequest","InvalidJSONContent","ServiceUnavailable",
  "NotAuthenticated","InvalidXboxLiveToken","InvalidSignature","AccountBanned","APIRequestLimitExceeded",
  "BadRequest","Unauthorized","Forbidden","AccessDenied","TokenExpired","InvalidToken",
  "AuthenticationRequired","invalid_grant","invalid_request","unauthorized","ForbiddenOperationException"};
 for(unsigned i=0;i<sizeof(known)/sizeof(known[0]);i++)if(dcDiagEq(word,known[i])){dcDiagCopy(out,64,known[i]);return;}
}
