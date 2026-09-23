#include "storage/qrx_storage_network.h"
#include "storage/qrx_storage_p2p.h"
#include "qrxdb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "qrx_thread_compat.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#define close_socket closesocket
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#define close_socket close
#endif

static int secure_temp_open(char *path,size_t cap,FILE **out){
    if(!path||cap<64||!out)return -1;*out=NULL;
#ifdef _WIN32
    char dir[MAX_PATH],tmp[MAX_PATH];DWORD n=GetTempPathA(MAX_PATH,dir);if(!n||n>=MAX_PATH||!GetTempFileNameA(dir,"QRX",0,tmp))return -1;if(strlen(tmp)+1>cap){DeleteFileA(tmp);return -1;}snprintf(path,cap,"%s",tmp);FILE*f=fopen(path,"wb");if(!f){DeleteFileA(tmp);return -1;}*out=f;return 0;
#else
    snprintf(path,cap,"/tmp/qrx-storage-XXXXXX");int fd=mkstemp(path);if(fd<0)return -1;FILE*f=fdopen(fd,"wb");if(!f){close(fd);unlink(path);return -1;}*out=f;return 0;
#endif
}

static int send_all(int fd,const void*b,size_t n){const char*p=b;while(n){int w=(int)send(fd,p,(int)n,0);if(w<=0)return -1;p+=w;n-=w;}return 0;}
static int recv_all(int fd,void*b,size_t n){char*p=b;while(n){int r=(int)recv(fd,p,(int)n,0);if(r<=0)return -1;p+=r;n-=r;}return 0;}
static int parse_endpoint(const char*e,char*h,size_t hn,char*p,size_t pn){if(!e||strncmp(e,"qrxp2p://",9))return -2;const char*s=e+9,*c=strrchr(s,':');if(!c||c==s||!*++c)return -1;size_t n=(size_t)((c-1)-s);if(n+1>hn||strlen(c)+1>pn)return -1;memcpy(h,s,n);h[n]=0;snprintf(p,pn,"%s",c);return 0;}
static int connect_ep(const char*e){char host[256],port[16];int pr=parse_endpoint(e,host,sizeof(host),port,sizeof(port));if(pr)return pr;struct addrinfo hints,*res=NULL,*it;memset(&hints,0,sizeof(hints));hints.ai_socktype=SOCK_STREAM;hints.ai_family=AF_UNSPEC;if(getaddrinfo(host,port,&hints,&res))return -1;int fd=-1;for(it=res;it;it=it->ai_next){fd=(int)socket(it->ai_family,it->ai_socktype,it->ai_protocol);if(fd<0)continue;if(connect(fd,it->ai_addr,(socklen_t)it->ai_addrlen)==0)break;close_socket(fd);fd=-1;}freeaddrinfo(res);return fd;}
int qrx_storage_network_fetch_range(void*v,const QrxShardProviderSource*s,const uint8_t ignored[64],uint64_t off,size_t len,uint8_t**out,size_t*outn){(void)ignored;if(!v||!s||!s->endpoint||!s->object_id_hex||len>QRX_STORAGE_NET_MAX_RANGE||!out||!outn)return -1;QrxStorageNetworkFetchCtx*c=v;int fd=connect_ep(s->endpoint);if(fd<0)return fd;char req[1024];int n=snprintf(req,sizeof(req),"QRXSTOR1 GET\ncontract=%s\nshard=%u\nobject=%s\noffset=%llu\nlength=%zu\n\n",c->contract_id,s->source.shard_index,s->object_id_hex,(unsigned long long)off,len);if(n<=0||n>=(int)sizeof(req)||send_all(fd,req,(size_t)n)){close_socket(fd);return -1;}char line[128];size_t pos=0;while(pos+1<sizeof(line)){char ch;if(recv_all(fd,&ch,1)){close_socket(fd);return -1;}line[pos++]=ch;if(ch=='\n')break;}line[pos]=0;size_t got=0;if(sscanf(line,"OK %zu",&got)!=1||got>len){close_socket(fd);return -1;}uint8_t*b=malloc(got?got:1);if(!b||recv_all(fd,b,got)){free(b);close_socket(fd);return -1;}close_socket(fd);*out=b;*outn=got;return 0;}

int qrx_storage_network_upload_file(const QrxShardProviderSource*s,const char*cid,const char*path){if(!s||!s->endpoint||!s->object_id_hex||!cid||!path)return -1;FILE*f=fopen(path,"rb");if(!f)return -1;if(fseek(f,0,SEEK_END)){fclose(f);return -1;}long ln=ftell(f);if(ln<0||fseek(f,0,SEEK_SET)){fclose(f);return -1;}int fd=connect_ep(s->endpoint);if(fd<0){fclose(f);return fd;}char req[1024];int n=snprintf(req,sizeof(req),"QRXSTOR1 PUT\ncontract=%s\nshard=%u\nobject=%s\nlength=%llu\n\n",cid,s->source.shard_index,s->object_id_hex,(unsigned long long)ln);if(n<=0||n>=(int)sizeof(req)||send_all(fd,req,(size_t)n)){fclose(f);close_socket(fd);return -1;}char buf[65536];long rem=ln;while(rem>0){size_t want=(size_t)(rem>(long)sizeof(buf)?sizeof(buf):rem);size_t r=fread(buf,1,want,f);if(r!=want||send_all(fd,buf,r)){fclose(f);close_socket(fd);return -1;}rem-=(long)r;}fclose(f);char line[64];size_t pos=0;while(pos+1<sizeof(line)){char ch;if(recv_all(fd,&ch,1)){close_socket(fd);return -1;}line[pos++]=ch;if(ch=='\n')break;}line[pos]=0;close_socket(fd);return !strncmp(line,"OK",2)?0:-1;}
typedef struct{const QrxShardProviderSource*s;const char*cid;const char*path;int rc;} UpW;
static void*up_worker(void*v){UpW*w=v;w->rc=qrx_storage_network_upload_file(w->s,w->cid,w->path);return NULL;}
int qrx_storage_network_upload_many(const QrxShardProviderSource*s,const char*const*paths,size_t n,const char*cid,size_t*ok){if(!s||!paths||!n||n>QRX_STORAGE_MAX_FETCH_SOURCES||!cid)return -1;pthread_t th[QRX_STORAGE_MAX_FETCH_SOURCES];UpW w[QRX_STORAGE_MAX_FETCH_SOURCES];size_t launched=0;for(size_t i=0;i<n;i++){w[i]=(UpW){&s[i],cid,paths[i],-1};if(pthread_create(&th[i],NULL,up_worker,&w[i]))break;launched++;}size_t good=0;for(size_t i=0;i<launched;i++){pthread_join(th[i],NULL);if(!w[i].rc)good++;}if(ok)*ok=good;return launched==n&&good==n?0:-1;}
static int recv_header(int fd,char*b,size_t cap){size_t n=0;int nl=0;while(n+1<cap){char c;if(recv_all(fd,&c,1))return -1;b[n++]=c;if(c=='\n'){if(nl)break;nl=1;}else if(c!='\r')nl=0;}b[n]=0;return nl?0:-1;}
int qrx_storage_qrxp2p_serve_fd(int fd,void*dbv,void*fsv,const char*provider){if(fd<0||!dbv||!fsv||!provider)return -1;char h[2048];if(recv_header(fd,h,sizeof(h))){close_socket(fd);return -1;}int is_put=!strncmp(h,"QRXSTOR1 PUT",12);char cid[129]={0},oid[65]={0};unsigned sh=0;unsigned long long off=0,total=0;size_t len=0;char*save=NULL;for(char*ln=strtok_r(h,"\n",&save);ln;ln=strtok_r(NULL,"\n",&save)){sscanf(ln,"contract=%128s",cid);sscanf(ln,"shard=%u",&sh);sscanf(ln,"object=%64s",oid);sscanf(ln,"offset=%llu",&off);sscanf(ln,"length=%llu",&total);}if(is_put){char tmpn[1024];FILE*f=NULL;if(secure_temp_open(tmpn,sizeof(tmpn),&f)){close_socket(fd);return -1;}char b[65536];unsigned long long rem=total;int rc=0;while(rem){size_t want=(size_t)(rem>sizeof(b)?sizeof(b):rem);if(recv_all(fd,b,want)||fwrite(b,1,want,f)!=want){rc=-1;break;}rem-=want;}if(fclose(f))rc=-1;if(!rc)rc=qrx_storage_p2p_write_authorized_file((QrxDB*)dbv,(QrxStorageFs*)fsv,provider,cid,sh,oid,tmpn);remove(tmpn);send_all(fd,rc?"ERR\n":"OK\n",rc?4:3);close_socket(fd);return rc;}len=(size_t)total;unsigned char*out=NULL;size_t outn=0;int rc=qrx_storage_p2p_read_authorized((QrxDB*)dbv,(QrxStorageFs*)fsv,provider,cid,sh,oid,(uint64_t)off,len,&out,&outn);char resp[64];if(rc){send_all(fd,"ERR\n",4);close_socket(fd);free(out);return -1;}int rn=snprintf(resp,sizeof(resp),"OK %zu\n",outn);if(send_all(fd,resp,(size_t)rn)||send_all(fd,out,outn))rc=-1;free(out);close_socket(fd);return rc;}

int qrx_storage_qrxp2p_serve_once(int lfd,void*dbv,void*fsv,const char*provider){struct sockaddr_storage ss;socklen_t sl=sizeof(ss);int fd=(int)accept(lfd,(struct sockaddr*)&ss,&sl);if(fd<0)return -1;return qrx_storage_qrxp2p_serve_fd(fd,dbv,fsv,provider);}
