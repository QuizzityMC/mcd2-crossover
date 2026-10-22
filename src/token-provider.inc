struct PD {void*async;U64 size;void*buffer;void*context;};
struct TokenData {U64 tokenSize,signatureSize;void*token;void*signature;};
struct Op {int kind,wide,index;struct TokenTrace diagnostic;char token[16384];};
static char addIdentity,tokenIdentity;
static int provider(unsigned op,const struct PD*d){struct Op*c=d->context;
 if(op==0)return aschedule(d->async,0);
 if(op==1){int r=c->kind==2?forceRenew():0;
  if(!r&&!live())r=NOUSER;
  if(!r&&c->kind==2){AcquireSRWLockExclusive(&credLock);copy(c->token,cred.tokens[c->index],16384);ReleaseSRWLockExclusive(&credLock);}
  if(c->kind)tokenTraceEmit(&c->diagnostic,"complete",r);
  U64 n=c->kind==0?sizeof(void*):sizeof(struct TokenData)+(len(c->token)+1)*(c->wide?2:1);acomplete(d->async,r,r<0?0:n);return 0;}
 if(op==2){if(c->kind==0){*(void**)d->buffer=&handleMarker;return 0;}
 tokenTraceEmit(&c->diagnostic,"result",0);
 struct TokenData*t=d->buffer;U64 n=len(c->token);t->tokenSize=n+1;t->signatureSize=0;t->token=t+1;t->signature=0;
 if(c->wide){unsigned short*p=t->token;for(U64 i=0;i<=n;i++)p[i]=(unsigned char)c->token[i];}else copy(t->token,c->token,n+1);return 0;}
 if(op==3)return 0; // Work is bounded and already scheduled; it completes normally.
 if(op==4){memset(c,0,sizeof(*c));HeapFree(GetProcessHeap(),0,c);return 0;}
 return INVALID;
}
static int start(void*a,int kind,const char*t,int wide){if(!a||!initAsync())return FAIL;struct Op*c=HeapAlloc(GetProcessHeap(),8,sizeof(*c));if(!c)return FAIL;c->kind=kind;c->wide=wide;if(t)copy(c->token,t,len(t)+1);int r=abegin(a,c,kind?&tokenIdentity:&addIdentity,kind?"RealXboxToken":"RealXboxUser",provider);if(r<0){memset(c,0,sizeof(*c));HeapFree(GetProcessHeap(),0,c);}return r;}
static int startToken(void*a,int index,int wide,int refresh,const struct TokenTrace*diagnostic){
 if(!a||!initAsync())return FAIL;struct Op*c=HeapAlloc(GetProcessHeap(),8,sizeof(*c));if(!c)return FAIL;
 copy(&c->diagnostic,diagnostic,sizeof(c->diagnostic));c->kind=refresh?2:1;c->wide=wide;c->index=index;AcquireSRWLockExclusive(&credLock);copy(c->token,cred.tokens[index],16384);ReleaseSRWLockExclusive(&credLock);
 int r=abegin(a,c,&tokenIdentity,"RealXboxToken",provider);if(r<0){memset(c,0,sizeof(*c));HeapFree(GetProcessHeap(),0,c);}return r;
}
