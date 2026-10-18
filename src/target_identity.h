/* Laboratory Windows ABI declarations. No image paths are emitted. */
typedef unsigned short W;
typedef struct { D low, high; } FT;
typedef struct { D attrs; FT created, accessed, written; D volume, size_high,
    size_low, links, index_high, index_low; } FI;
I D GetEnvironmentVariableW(const W*, W*, D);
I int QueryFullProcessImageNameW(H,D,W*,D*);
I H CreateFileW(const W*,D,D,void*,D,D,H);
I int GetFileInformationByHandle(H,FI*);
I int GetProcessTimes(H,FT*,FT*,FT*,FT*);
static W expected_path[32768], actual_path[32768];
static FI expected_file;
static int file_identity(const W*path,FI*out){
    H f=CreateFileW(path,0,7,0,3,0,0);
    if(f==(H)(U)-1)return 0;
    int ok=GetFileInformationByHandle(f,out);CloseHandle(f);return ok;
}
static int prepare_expected(void){
    D n=GetEnvironmentVariableW((const W*)L"MCD2_CAPTURE_EXPECTED_IMAGE",expected_path,32768);
    return n && n<32768 && file_identity(expected_path,&expected_file);
}
static int matching_image(H process){
    D n=32768;FI f;
    if(!QueryFullProcessImageNameW(process,0,actual_path,&n))return -1;
    if(!file_identity(actual_path,&f))return -1;
    return f.volume==expected_file.volume && f.index_high==expected_file.index_high
        && f.index_low==expected_file.index_low;
}
static U process_created(H process){
    FT c,e,k,u;if(!GetProcessTimes(process,&c,&e,&k,&u))return 0;
    return ((U)c.high<<32)|c.low;
}
static U expected_created(void){
    W b[32];D n=GetEnvironmentVariableW((const W*)L"MCD2_CAPTURE_EXPECTED_CREATED",b,32);
    if(!n||n>=32)return 0;
    U v=0;for(D i=0;i<n;i++){if(b[i]<'0'||b[i]>'9')return 0;
        U next=v*10+(b[i]-'0');if(next<v)return 0;v=next;}return v;
}
