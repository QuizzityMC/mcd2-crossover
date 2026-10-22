static int domain(const char*h,const char*d){unsigned n=len(h),m=len(d);return eq(h,d)||(n>m&&h[n-m-1]=='.'&&eq(h+n-m,d));}
static int tokenIndex(const char*url){char h[256]={0};if(!url)return -1;const char*p="https://";while(*p)if(*url++!=*p++)return -1;unsigned n=0;while(*url&&*url!='/'&&*url!='?'&&*url!='#'){char c=*url++;if(n>=254||c==':'||c=='@'||c=='\\')return -1;h[n++]=(c>='A'&&c<='Z')?c+32:c;}
 /* Host and operation are logged through the bounded structured event. */
 if(eq(h,"api.minecraftservices.com"))return 1;
 if(domain(h,"playfabapi.com"))return 2;
 if(domain(h,"xboxlive.com"))return 0;
 char message[256]={0};append(message,256,"Refused token host: ");append(message,256,"other");loghr(message,NOTIMPL);return -1;
}
static int tokenRequest(void*u,unsigned opts,const char*method,const char*url,void*a,int wide){
 nativeHttpObserve();struct TokenTrace diagnostic;tokenTraceStart(&diagnostic,url,method,opts);int r=0;
 if(opts&~1U)r=NOTIMPL;
 else if(u!=&handleMarker||!url||(!(opts&1)&&!valid(u)))r=NOUSER;
 int idx=r?-1:tokenIndex(url);
 if(!r&&idx<0)r=NOTIMPL;
 if(!r){loghr("Service token requested",idx);r=startToken(a,idx,wide,opts&1,&diagnostic);}
 if(r<0)tokenTraceEmit(&diagnostic,"complete",r);return r;
}
static int tokenAsync(void*s,void*u,unsigned opts,const char*method,const char*url,U64 nh,const void*headers,U64 nb,const void*body,void*a){
 return tokenRequest(u,opts,method,url,a,0);
}
static int token16(void*s,void*u,unsigned opts,const unsigned short*method,const unsigned short*url,U64 nh,const void*headers,U64 nb,const void*body,void*a){
 char v[2048]={0},m[16]={0};unsigned i=0;
 if(url){for(;i<2047&&url[i];i++){if(url[i]>127)break;v[i]=(char)url[i];}
  if(url[i]){int r=url[i]>127?NOTIMPL:INVALID;struct TokenTrace d;tokenTraceStart(&d,0,0,opts);tokenTraceEmit(&d,"complete",r);return r;}}
 if(method){for(i=0;i<15&&method[i];i++){if(method[i]>127)break;m[i]=(char)method[i];}if(method[i])m[0]=0;}
 return tokenRequest(u,opts,m,url?v:0,a,1);
}
static int tokenSize(void*s,void*a,U64*n){return asize(a,n);}
static int tokenResult(void*s,void*a,U64 size,void*b,void**ptr,U64*used){if(!ptr)return INVALID;*ptr=0;int r=aresult(a,&tokenIdentity,size,b,used);if(r>=0)*ptr=b;loghr("Service token result",r);return r;}
