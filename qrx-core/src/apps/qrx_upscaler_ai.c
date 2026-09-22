#include "apps/qrx_upscaler_ai.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#if defined(_MSC_VER) && !defined(S_ISREG)
#define S_ISREG(mode) (((mode) & _S_IFMT) == _S_IFREG)
#endif
#include <ctype.h>
#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#include <sys/wait.h>
#endif

/* Minimal SHA-256 used only for local model-integrity verification. */
typedef struct { uint32_t h[8]; uint64_t n; unsigned char b[64]; size_t z; } S256;
static uint32_t rotr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void sblk(S256*s,const unsigned char*p){uint32_t w[64];for(int i=0;i<16;i++)w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];for(int i=16;i<64;i++){uint32_t a=rotr(w[i-15],7)^rotr(w[i-15],18)^(w[i-15]>>3),b=rotr(w[i-2],17)^rotr(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+a+w[i-7]+b;}uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];for(int i=0;i<64;i++){uint32_t S1=rotr(e,6)^rotr(e,11)^rotr(e,25),ch=(e&f)^((~e)&g),t1=h+S1+ch+K[i]+w[i],S0=rotr(a,2)^rotr(a,13)^rotr(a,22),maj=(a&b)^(a&c)^(b&c),t2=S0+maj;h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;}
static void sinit(S256*s){static const uint32_t H[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memset(s,0,sizeof(*s));memcpy(s->h,H,sizeof(H));}
static void supd(S256*s,const void*v,size_t n){const unsigned char*p=v;s->n+=(uint64_t)n*8;while(n){size_t k=64-s->z;if(k>n)k=n;memcpy(s->b+s->z,p,k);s->z+=k;p+=k;n-=k;if(s->z==64){sblk(s,s->b);s->z=0;}}}
static void sfin(S256*s,unsigned char out[32]){s->b[s->z++]=0x80;if(s->z>56){while(s->z<64)s->b[s->z++]=0;sblk(s,s->b);s->z=0;}while(s->z<56)s->b[s->z++]=0;for(int i=7;i>=0;i--)s->b[s->z++]=(unsigned char)(s->n>>(i*8));sblk(s,s->b);for(int i=0;i<8;i++){out[i*4]=(unsigned char)(s->h[i]>>24);out[i*4+1]=(unsigned char)(s->h[i]>>16);out[i*4+2]=(unsigned char)(s->h[i]>>8);out[i*4+3]=(unsigned char)s->h[i];}}
static int file_sha256(const char*p,char hex[65]){FILE*f=fopen(p,"rb");if(!f)return-1;S256 s;sinit(&s);unsigned char b[131072],h[32];for(;;){size_t n=fread(b,1,sizeof(b),f);if(n)supd(&s,b,n);if(n<sizeof(b)){if(ferror(f)){fclose(f);return-1;}break;}}fclose(f);sfin(&s,h);static const char*x="0123456789abcdef";for(int i=0;i<32;i++){hex[i*2]=x[h[i]>>4];hex[i*2+1]=x[h[i]&15];}hex[64]=0;return 0;}
static int regular(const char*p){struct stat s;return p&&*p&&stat(p,&s)==0&&S_ISREG(s.st_mode);}
static int absolute_path(const char*p){if(!p||!*p)return 0;
#ifdef _WIN32
return (isalpha((unsigned char)p[0])&&p[1]==':')||p[0]=='\\';
#else
return p[0]=='/';
#endif
}
static void join(char*out,size_t n,const char*a,const char*b){snprintf(out,n,"%s%s%s",a,(a&&*a&&a[strlen(a)-1]=='/')?"":"/",b);}
static void default_model_dir(char*out,size_t n){const char*e=getenv("QRX_UPSCALER_MODEL_DIR");if(e&&*e){snprintf(out,n,"%s",e);return;}const char*h=getenv("HOME");if(!h)h=".";
#if defined(__APPLE__)
snprintf(out,n,"%s/Library/Application Support/QRX/upscaler/models",h);
#elif defined(_WIN32)
const char*a=getenv("LOCALAPPDATA");snprintf(out,n,"%s\\QRX\\upscaler\\models",a&&*a?a:".");
#else
snprintf(out,n,"%s/.local/share/qrx/upscaler/models",h);
#endif
}
static void runtime_path(char*out,size_t n){const char*e=getenv("QRX_UPSCALER_NCNN_RUNTIME");if(e&&absolute_path(e)&&regular(e)){snprintf(out,n,"%s",e);return;}
#if defined(__APPLE__)
char userrt[QRX_UPS_AI_PATH_MAX]; const char*h=getenv("HOME");
if(h&&*h){snprintf(userrt,sizeof(userrt),"%s/Library/Application Support/QRX/upscaler/runtime/realesrgan-ncnn-vulkan",h);if(regular(userrt)){snprintf(out,n,"%s",userrt);return;}}
const char*c[]={"/opt/homebrew/bin/realesrgan-ncnn-vulkan","/usr/local/bin/realesrgan-ncnn-vulkan"};
#elif defined(_WIN32)
const char*c[]={"C:/Program Files/QRX/bin/realesrgan-ncnn-vulkan.exe"};
#else
const char*c[]={"/usr/local/bin/realesrgan-ncnn-vulkan","/usr/bin/realesrgan-ncnn-vulkan"};
#endif
for(size_t i=0;i<sizeof(c)/sizeof(c[0]);i++)if(regular(c[i])){snprintf(out,n,"%s",c[i]);return;}out[0]=0;}
static char*trim(char*s){while(*s&&isspace((unsigned char)*s))s++;char*e=s+strlen(s);while(e>s&&isspace((unsigned char)e[-1]))*--e=0;return s;}
typedef struct{char id[96],param[256],weights[256],ph[65],wh[65],license[96],source[384],release[96],archive_sha[65];int scale;} Mf;
static int parse_manifest(const char*p,Mf*m,char*err,size_t ec){memset(m,0,sizeof(*m));FILE*f=fopen(p,"rb");if(!f){snprintf(err,ec,"manifest missing");return-1;}char l[1024],format[64]={0};while(fgets(l,sizeof(l),f)){char*s=trim(l);if(!*s||*s=='#')continue;char*eq=strchr(s,'=');if(!eq)continue;*eq++=0;s=trim(s);eq=trim(eq);if(!strcmp(s,"format"))snprintf(format,sizeof(format),"%s",eq);else if(!strcmp(s,"id"))snprintf(m->id,sizeof(m->id),"%s",eq);else if(!strcmp(s,"scale"))m->scale=atoi(eq);else if(!strcmp(s,"param"))snprintf(m->param,sizeof(m->param),"%s",eq);else if(!strcmp(s,"weights"))snprintf(m->weights,sizeof(m->weights),"%s",eq);else if(!strcmp(s,"param_sha256"))snprintf(m->ph,sizeof(m->ph),"%s",eq);else if(!strcmp(s,"weights_sha256"))snprintf(m->wh,sizeof(m->wh),"%s",eq);else if(!strcmp(s,"license_id"))snprintf(m->license,sizeof(m->license),"%s",eq);else if(!strcmp(s,"provenance_source_url"))snprintf(m->source,sizeof(m->source),"%s",eq);else if(!strcmp(s,"provenance_release"))snprintf(m->release,sizeof(m->release),"%s",eq);else if(!strcmp(s,"provenance_archive_sha256"))snprintf(m->archive_sha,sizeof(m->archive_sha),"%s",eq);}fclose(f);if((strcmp(format,"qrx-upscaler-model-v1")&&strcmp(format,"qrx-upscaler-model-v2"))||!m->id[0]||(m->scale!=2&&m->scale!=4)||!m->param[0]||!m->weights[0]||strlen(m->ph)!=64||strlen(m->wh)!=64||!m->license[0]||!strncmp(m->license,"REVIEW-",7)||!strncmp(m->license,"UNKNOWN",7)){snprintf(err,ec,"invalid qrx-upscaler-model manifest");return-1;}if(!strcmp(format,"qrx-upscaler-model-v2")&&(!m->source[0]||!m->release[0]||strlen(m->archive_sha)!=64)){snprintf(err,ec,"qrx-upscaler-model-v2 missing provenance");return-1;}return 0;}
int qrx_ups_ai_verify_manifest(const char*mp,char*err,size_t ec){Mf m;if(parse_manifest(mp,&m,err,ec))return-1;char dir[1024],pp[1300],wp[1300],got[65];snprintf(dir,sizeof(dir),"%s",mp);char*s1=strrchr(dir,'/');
#ifdef _WIN32
char*s2=strrchr(dir,'\\');if(!s1||(s2&&s2>s1))s1=s2;
#endif
if(s1)*s1=0;else snprintf(dir,sizeof(dir),".");join(pp,sizeof(pp),dir,m.param);join(wp,sizeof(wp),dir,m.weights);if(file_sha256(pp,got)||strcmp(got,m.ph)){snprintf(err,ec,"param SHA-256 mismatch");return-1;}if(file_sha256(wp,got)||strcmp(got,m.wh)){snprintf(err,ec,"weights SHA-256 mismatch");return-1;}if(err&&ec)*err=0;return 0;}
static int find_manifest(const char*dir,int scale,char*out,size_t n,Mf*m,int*verified){const char*names2[]={"realesrgan-x2plus.qrxmodel","qrx-realesrgan-x2.qrxmodel"};const char*names4[]={"realesrgan-x4plus.qrxmodel","qrx-realesrgan-x4.qrxmodel"};const char**a=scale==2?names2:names4;size_t z=2;for(size_t i=0;i<z;i++){join(out,n,dir,a[i]);if(regular(out)){char e[160];if(parse_manifest(out,m,e,sizeof(e))==0&&m->scale==scale){*verified=qrx_ups_ai_verify_manifest(out,e,sizeof(e))==0;return 0;}}}out[0]=0;return-1;}
int qrx_ups_ai_status(QrxUpsAiStatus*out){if(!out)return-1;memset(out,0,sizeof(*out));snprintf(out->backend,sizeof(out->backend),"ncnn-vulkan");runtime_path(out->runtime_path,sizeof(out->runtime_path));out->runtime_installed=out->runtime_path[0]!=0;out->runtime_verified=out->runtime_installed;const char*rh=getenv("QRX_UPSCALER_RUNTIME_SHA256");if(out->runtime_installed&&rh&&*rh){char got[65];out->runtime_verified=(strlen(rh)==64&&file_sha256(out->runtime_path,got)==0&&!strcmp(got,rh));}default_model_dir(out->model_dir,sizeof(out->model_dir));char p[1200];Mf m;int v=0;if(!find_manifest(out->model_dir,2,p,sizeof(p),&m,&v)){out->model_x2_installed=1;out->model_x2_verified=v;snprintf(out->model_x2_id,sizeof(out->model_x2_id),"%s",m.id);}v=0;if(!find_manifest(out->model_dir,4,p,sizeof(p),&m,&v)){out->model_x4_installed=1;out->model_x4_verified=v;snprintf(out->model_x4_id,sizeof(out->model_x4_id),"%s",m.id);}out->ai_ready=out->runtime_installed&&out->runtime_verified&&((out->model_x2_installed&&out->model_x2_verified)||(out->model_x4_installed&&out->model_x4_verified));if(out->ai_ready)snprintf(out->status,sizeof(out->status),"Local AI ready: ncnn Vulkan runtime and at least one SHA-256 verified model are installed.");else if(!out->runtime_installed)snprintf(out->status,sizeof(out->status),"AI runtime missing. Set QRX_UPSCALER_NCNN_RUNTIME to an absolute realesrgan-ncnn-vulkan path or install it in a supported location.");else if(!out->runtime_verified)snprintf(out->status,sizeof(out->status),"AI runtime integrity verification failed.");else snprintf(out->status,sizeof(out->status),"Runtime found, but no verified 2x/4x QRX model manifest is installed in %s.",out->model_dir);return 0;}
static int runv(const char*exe,char*const av[]){
#ifdef _WIN32
intptr_t r=_spawnv(_P_WAIT,exe,(const char*const*)av);return r==0?0:-1;
#else
pid_t p=fork();if(p<0)return-1;if(p==0){execv(exe,av);_exit(127);}int st=0;if(waitpid(p,&st,0)<0)return-1;return WIFEXITED(st)&&WEXITSTATUS(st)==0?0:-1;
#endif
}
int qrx_ups_ai_run_image(const char*in,const char*outp,int scale,unsigned tile,const char*model_id){if(!in||!outp||(scale!=2&&scale!=4))return-1;QrxUpsAiStatus st;if(qrx_ups_ai_status(&st)||!st.runtime_installed)return-2;char mp[1200];Mf m;int verified=0;if(find_manifest(st.model_dir,scale,mp,sizeof(mp),&m,&verified)||!verified)return-3;if(model_id&&*model_id&&strcmp(model_id,m.id))return-4;char modelpath[1024];snprintf(modelpath,sizeof(modelpath),"%s",st.model_dir);char scale_s[16],tile_s[32];snprintf(scale_s,sizeof(scale_s),"%d",scale);snprintf(tile_s,sizeof(tile_s),"%u",tile?tile:0);char*av[]={st.runtime_path,(char*)"-i",(char*)in,(char*)"-o",(char*)outp,(char*)"-s",scale_s,(char*)"-t",tile_s,(char*)"-m",modelpath,(char*)"-n",m.id,(char*)"-g",(char*)"auto",NULL};return runv(st.runtime_path,av)==0?0:-5;}
