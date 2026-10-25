// aegis crash-harness tracing shim (LD_PRELOAD). Logs write/sync/namespace ops under AEGIS_ROOT to AEGIS_LOG.
// Text log, one op per line; data hex-encoded. Not a filesystem: ALICE-style logical-op tracing.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <errno.h>
static FILE *logf; static char root[512]; static pthread_mutex_t mu=PTHREAD_MUTEX_INITIALIZER;
static unsigned char fdsync[65536]; // 1=O_DSYNC/O_SYNC
#define REAL(name) static typeof(&name) real=NULL; if(!real) real=dlsym(RTLD_NEXT,#name)
static __thread int busy;
static void init(void){ if(logf) return; const char*l=getenv("AEGIS_LOG"); const char*r=getenv("AEGIS_ROOT"); if(!l||!r) return;
  strncpy(root,r,sizeof root-1); int(*ro)(const char*,int,...)=dlsym(RTLD_NEXT,"open"); (void)ro; FILE*(*fo)(const char*,const char*)=dlsym(RTLD_NEXT,"fopen"); logf=fo(l,"a"); setvbuf(logf,NULL,_IOFBF,1<<20);}
static int inroot(const char*p){ return root[0] && !strncmp(p,root,strlen(root)); }
static int fdpath(int fd,char*out,size_t n){ char l[64]; snprintf(l,sizeof l,"/proc/self/fd/%d",fd); ssize_t k=readlink(l,out,n-1); if(k<0) return 0; out[k]=0; return inroot(out);}
static void absp(int dirfd,const char*p,char*out,size_t n){ if(p[0]=='/'){strncpy(out,p,n-1);out[n-1]=0;return;} char base[512]; if(dirfd==AT_FDCWD){ if(!getcwd(base,sizeof base)) base[0]=0;} else { char l[64]; snprintf(l,sizeof l,"/proc/self/fd/%d",dirfd); ssize_t k=readlink(l,base,sizeof base-1); base[k>0?k:0]=0;} snprintf(out,n,"%s/%s",base,p); }
static void hexw(const unsigned char*d,size_t n){ static const char*h="0123456789abcdef"; for(size_t i=0;i<n;i++){fputc(h[d[i]>>4],logf);fputc(h[d[i]&15],logf);} }
#define LOCK() pthread_mutex_lock(&mu)
#define UNLOCK() pthread_mutex_unlock(&mu)
static void logw(const char*p,long off,const unsigned char*d,size_t n){ fprintf(logf,"W %s %ld %zu ",p,off,n); hexw(d,n); fputc('\n',logf);}
void aegis_mark(long i){ init(); if(!logf) return; LOCK(); fprintf(logf,"M %ld\n",i); fflush(logf); UNLOCK(); }
static int doopen(int dirfd,const char*path,int flags,mode_t mode,int rfd){
  init(); if(rfd>=0 && rfd<65536) fdsync[rfd]=(flags&(O_DSYNC|O_SYNC))?1:0;
  if(rfd>=0 && logf){ char a[1024]; absp(dirfd,path,a,sizeof a); if(inroot(a)){ LOCK(); fprintf(logf,"O %s %d\n",a,(flags&O_TRUNC)?1:0); UNLOCK(); } } return rfd; }
int open64(const char*path,int flags,...){ mode_t m=0; if(flags&(O_CREAT|O_TMPFILE)){va_list ap;va_start(ap,flags);m=va_arg(ap,mode_t);va_end(ap);} REAL(open64); int fd=real(path,flags,m); return doopen(AT_FDCWD,path,flags,m,fd);}
int open(const char*path,int flags,...){ mode_t m=0; if(flags&(O_CREAT|O_TMPFILE)){va_list ap;va_start(ap,flags);m=va_arg(ap,mode_t);va_end(ap);} REAL(open); int fd=real(path,flags,m); return doopen(AT_FDCWD,path,flags,m,fd);}
int openat64(int d,const char*path,int flags,...){ mode_t m=0; if(flags&(O_CREAT|O_TMPFILE)){va_list ap;va_start(ap,flags);m=va_arg(ap,mode_t);va_end(ap);} REAL(openat64); int fd=real(d,path,flags,m); return doopen(d,path,flags,m,fd);}
int openat(int d,const char*path,int flags,...){ mode_t m=0; if(flags&(O_CREAT|O_TMPFILE)){va_list ap;va_start(ap,flags);m=va_arg(ap,mode_t);va_end(ap);} REAL(openat); int fd=real(d,path,flags,m); return doopen(d,path,flags,m,fd);}
int creat64(const char*p,mode_t m){ return open64(p,O_CREAT|O_WRONLY|O_TRUNC,m);}
static void sync_after(int fd,const char*p){ if(fd>=0&&fd<65536&&fdsync[fd]) fprintf(logf,"S %s\n",p); }
ssize_t pwrite64(int fd,const void*b,size_t n,off_t off){ REAL(pwrite64); ssize_t r=real(fd,b,n,off); init(); char p[1024]; if(r>0&&logf&&fdpath(fd,p,sizeof p)){LOCK(); logw(p,off,b,r); sync_after(fd,p); UNLOCK();} return r;}
ssize_t pwrite(int fd,const void*b,size_t n,off_t off){ return pwrite64(fd,b,n,off);}
ssize_t write(int fd,const void*b,size_t n){ REAL(write); init(); char p[1024]; off_t off=-1; int lg=0; if(logf&&fd>2&&fdpath(fd,p,sizeof p)){ lg=1; int fl=fcntl(fd,F_GETFL); if(fl&O_APPEND){struct stat st; fstat(fd,&st); off=st.st_size;} else off=lseek(fd,0,SEEK_CUR);} ssize_t r=real(fd,b,n); if(lg&&r>0){LOCK(); logw(p,off,b,r); sync_after(fd,p); UNLOCK();} return r;}
ssize_t pwritev64(int fd,const struct iovec*v,int c,off_t off){ REAL(pwritev64); ssize_t r=real(fd,v,c,off); init(); char p[1024]; if(r>0&&logf&&fdpath(fd,p,sizeof p)){LOCK(); size_t left=r; off_t o=off; for(int i=0;i<c&&left;i++){size_t k=v[i].iov_len<left?v[i].iov_len:left; logw(p,o,v[i].iov_base,k); o+=k; left-=k;} sync_after(fd,p); UNLOCK();} return r;}
ssize_t pwritev(int fd,const struct iovec*v,int c,off_t off){ return pwritev64(fd,v,c,off);}
ssize_t writev(int fd,const struct iovec*v,int c){ REAL(writev); init(); char p[1024]; off_t off=-1; int lg=0; if(logf&&fd>2&&fdpath(fd,p,sizeof p)){ lg=1; int fl=fcntl(fd,F_GETFL); if(fl&O_APPEND){struct stat st; fstat(fd,&st); off=st.st_size;} else off=lseek(fd,0,SEEK_CUR);} ssize_t r=real(fd,v,c); if(lg&&r>0){LOCK(); size_t left=r; off_t o=off; for(int i=0;i<c&&left;i++){size_t k=v[i].iov_len<left?v[i].iov_len:left; logw(p,o,v[i].iov_base,k); o+=k; left-=k;} sync_after(fd,p); UNLOCK();} return r;}
static int dosync(int fd,int (*f)(int)){ init(); char p[1024]; int lg=logf&&fdpath(fd,p,sizeof p); int r=f(fd); if(lg&&r==0){LOCK(); fprintf(logf,"S %s\n",p); fflush(logf); UNLOCK();} return r;}
int fsync(int fd){ REAL(fsync); return dosync(fd,real);} int fdatasync(int fd){ REAL(fdatasync); return dosync(fd,real);}
int ftruncate64(int fd,off_t len){ REAL(ftruncate64); init(); char p[1024]; int lg=logf&&fdpath(fd,p,sizeof p); int r=real(fd,len); if(lg&&r==0){LOCK(); fprintf(logf,"T %s %ld\n",p,(long)len); UNLOCK();} return r;}
int ftruncate(int fd,off_t len){ return ftruncate64(fd,len);}
int fallocate64(int fd,int mode,off_t off,off_t len){ REAL(fallocate64); init(); char p[1024]; int lg=logf&&fdpath(fd,p,sizeof p); int r=real(fd,mode,off,len); if(lg&&r==0){LOCK(); fprintf(logf,"A %s %d %ld %ld\n",p,mode,(long)off,(long)len); UNLOCK();} return r;}
int fallocate(int fd,int mode,off_t off,off_t len){ return fallocate64(fd,mode,off,len);}
int posix_fallocate64(int fd,off_t off,off_t len){ REAL(posix_fallocate64); init(); char p[1024]; int lg=logf&&fdpath(fd,p,sizeof p); int r=real(fd,off,len); if(lg&&r==0){LOCK(); fprintf(logf,"A %s 0 %ld %ld\n",p,(long)off,(long)len); UNLOCK();} return r;}
int posix_fallocate(int fd,off_t off,off_t len){ return posix_fallocate64(fd,off,len);}
int rename(const char*a,const char*b){ REAL(rename); init(); int r=real(a,b); if(r==0&&logf){char x[1024],y[1024]; absp(AT_FDCWD,a,x,sizeof x); absp(AT_FDCWD,b,y,sizeof y); if(inroot(x)){LOCK(); fprintf(logf,"R %s %s\n",x,y); UNLOCK();}} return r;}
int renameat(int d1,const char*a,int d2,const char*b){ REAL(renameat); init(); int r=real(d1,a,d2,b); if(r==0&&logf){char x[1024],y[1024]; absp(d1,a,x,sizeof x); absp(d2,b,y,sizeof y); if(inroot(x)){LOCK(); fprintf(logf,"R %s %s\n",x,y); UNLOCK();}} return r;}
int renameat2(int d1,const char*a,int d2,const char*b,unsigned f){ int(*real)(int,const char*,int,const char*,unsigned)=dlsym(RTLD_NEXT,"renameat2"); init(); int r=real(d1,a,d2,b,f); if(r==0&&logf){char x[1024],y[1024]; absp(d1,a,x,sizeof x); absp(d2,b,y,sizeof y); if(inroot(x)){LOCK(); fprintf(logf,"R %s %s\n",x,y); UNLOCK();}} return r;}
int unlink(const char*p){ REAL(unlink); init(); int r=real(p); if(r==0&&logf){char x[1024]; absp(AT_FDCWD,p,x,sizeof x); if(inroot(x)){LOCK(); fprintf(logf,"U %s\n",x); UNLOCK();}} return r;}
int unlinkat(int d,const char*p,int fl){ REAL(unlinkat); init(); int r=real(d,p,fl); if(r==0&&logf){char x[1024]; absp(d,p,x,sizeof x); if(inroot(x)){LOCK(); fprintf(logf,"%s %s\n",(fl&AT_REMOVEDIR)?"X":"U",x); UNLOCK();}} return r;}
int mkdir(const char*p,mode_t m){ REAL(mkdir); init(); int r=real(p,m); if(r==0&&logf){char x[1024]; absp(AT_FDCWD,p,x,sizeof x); if(inroot(x)){LOCK(); fprintf(logf,"D %s\n",x); UNLOCK();}} return r;}
void* mmap64(void*a,size_t l,int pr,int fl,int fd,off_t o){ REAL(mmap64); init(); void*r=real(a,l,pr,fl,fd,o); char p[1024]; if(logf&&fd>=0&&(pr&PROT_WRITE)&&(fl&MAP_SHARED)&&fdpath(fd,p,sizeof p)){LOCK(); fprintf(logf,"MMAPW %s %zu\n",p,l); UNLOCK();} return r;}
void* mmap(void*a,size_t l,int pr,int fl,int fd,off_t o){ return mmap64(a,l,pr,fl,fd,o);}
int msync(void*a,size_t l,int f){ REAL(msync); init(); if(logf){LOCK(); fprintf(logf,"MSYNC\n"); UNLOCK();} return real(a,l,f);}
