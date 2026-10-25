use rustls::client::danger::HandshakeSignatureValid;
use std::sync::{Arc,atomic::{AtomicU64,Ordering}};
use std::time::{Duration,Instant};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::TcpStream};
use rustls::{ClientConfig,pki_types::ServerName,client::danger::*,pki_types::{CertificateDer,UnixTime},DigitallySignedStruct,SignatureScheme,Error};
#[derive(Debug)] struct NoV;
impl ServerCertVerifier for NoV{
 fn verify_server_cert(&self,_:&CertificateDer<'_>,_:&[CertificateDer<'_>],_:&ServerName<'_>,_:&[u8],_:UnixTime)->Result<ServerCertVerified,Error>{Ok(ServerCertVerified::assertion())}
 fn verify_tls12_signature(&self,_:&[u8],_:&CertificateDer<'_>,_:&DigitallySignedStruct)->Result<HandshakeSignatureValid,Error>{Ok(HandshakeSignatureValid::assertion())}
 fn verify_tls13_signature(&self,_:&[u8],_:&CertificateDer<'_>,_:&DigitallySignedStruct)->Result<HandshakeSignatureValid,Error>{Ok(HandshakeSignatureValid::assertion())}
 fn supported_verify_schemes(&self)->Vec<SignatureScheme>{rustls::crypto::aws_lc_rs::default_provider().signature_verification_algorithms.supported_schemes()}
}
struct Cnt{i:TcpStream,rx:Arc<AtomicU64>,tx:Arc<AtomicU64>}
impl tokio::io::AsyncRead for Cnt{fn poll_read(mut self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>,b:&mut tokio::io::ReadBuf<'_>)->std::task::Poll<std::io::Result<()>>{let before=b.filled().len();let r=std::pin::Pin::new(&mut self.i).poll_read(cx,b);if let std::task::Poll::Ready(Ok(()))=&r{let n=b.filled().len()-before;self.rx.fetch_add(n as u64,Ordering::Relaxed);}r}}
impl tokio::io::AsyncWrite for Cnt{fn poll_write(mut self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>,b:&[u8])->std::task::Poll<std::io::Result<usize>>{let r=std::pin::Pin::new(&mut self.i).poll_write(cx,b);if let std::task::Poll::Ready(Ok(n))=&r{self.tx.fetch_add(*n as u64,Ordering::Relaxed);}r}
fn poll_flush(mut self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<std::io::Result<()>>{std::pin::Pin::new(&mut self.i).poll_flush(cx)}
fn poll_shutdown(mut self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<std::io::Result<()>>{std::pin::Pin::new(&mut self.i).poll_shutdown(cx)}}
fn cfg(group:&str)->Arc<ClientConfig>{
 let mut p=rustls::crypto::aws_lc_rs::default_provider();
 p.kx_groups=match group{
  "x25519"=>vec![rustls::crypto::aws_lc_rs::kx_group::X25519],
  "mlkem"=>vec![rustls::crypto::aws_lc_rs::kx_group::X25519MLKEM768],
  _=>panic!()};
 let mut c=ClientConfig::builder_with_provider(Arc::new(p)).with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
  .dangerous().with_custom_certificate_verifier(Arc::new(NoV)).with_no_client_auth();
 c.resumption=rustls::client::Resumption::disabled();
 c.alpn_protocols=vec![b"http/1.1".to_vec()];
 Arc::new(c)
}
fn cpu_ms()->f64{ // process cpu via /proc/self/stat utime+stime
 let s=std::fs::read_to_string("/proc/self/stat").unwrap();let r=s.rsplit(')').next().unwrap();let f:Vec<&str>=r.split_whitespace().collect();
 (f[11].parse::<f64>().unwrap()+f[12].parse::<f64>().unwrap())*10.0}
#[tokio::main(flavor="multi_thread",worker_threads=4)]
async fn main(){
 let a:Vec<String>=std::env::args().collect();
 match a[1].as_str(){
 "hold"=>{ // hold addr n tls
  let addr=a[2].clone();let n:usize=a[3].parse().unwrap();let tls=a.get(4).map(|s|s=="tls").unwrap_or(false);
  let c=tokio_rustls::TlsConnector::from(cfg("x25519"));
  let mut hs=vec![];
  for _ in 0..n{let addr=addr.clone();let c=c.clone();hs.push(tokio::spawn(async move{
   let s=TcpStream::connect(&addr).await.unwrap();
   if tls{let s=c.connect(ServerName::try_from("localhost").unwrap(),s).await.unwrap();tokio::time::sleep(Duration::from_secs(3600)).await;drop(s);}
   else{tokio::time::sleep(Duration::from_secs(3600)).await;drop(s);}
  }));}
  println!("holding {}",n);tokio::time::sleep(Duration::from_secs(3600)).await;
 }
 "hs"=>{ // hs addr group seconds conc
  let addr=a[2].clone();let g=a[3].clone();let secs:u64=a[4].parse().unwrap();let conc:usize=a[5].parse().unwrap();
  let c=tokio_rustls::TlsConnector::from(cfg(&g));
  let cnt=Arc::new(AtomicU64::new(0));let rx=Arc::new(AtomicU64::new(0));let tx=Arc::new(AtomicU64::new(0));
  let lat=Arc::new(std::sync::Mutex::new(Vec::<f64>::new()));
  let t0=Instant::now();let c0=cpu_ms();
  let mut hs=vec![];
  for _ in 0..conc{let (addr,c,cnt,lat)=(addr.clone(),c.clone(),cnt.clone(),lat.clone());let (rx,tx)=(rx.clone(),tx.clone());hs.push(tokio::spawn(async move{
   while t0.elapsed().as_secs()<secs{
    let st=Instant::now();
    let s=TcpStream::connect(&addr).await.unwrap();
    let s=Cnt{i:s,rx:rx.clone(),tx:tx.clone()};let mut s=c.connect(ServerName::try_from("localhost").unwrap(),s).await.unwrap();
    // measure handshake bytes via rustls wire counters is not exposed; use TCP_INFO-less approach: shutdown, count by tcpdump separately
    let _=s.shutdown().await;
    lat.lock().unwrap().push(st.elapsed().as_secs_f64()*1000.0);
    cnt.fetch_add(1,Ordering::Relaxed);
   }
  }));}
  for h in hs{let _=h.await;}
  let n=cnt.load(Ordering::Relaxed);let el=t0.elapsed().as_secs_f64();
  let mut l=lat.lock().unwrap().clone();l.sort_by(|a,b|a.partial_cmp(b).unwrap());
  println!("group={} handshakes={} secs={:.2} hs/s={:.1} client_cpu_ms_per_hs={:.3} p50ms={:.2} p99ms={:.2}",g,n,el,n as f64/el,(cpu_ms()-c0)/n as f64,l[l.len()/2],l[(l.len() as f64*0.99) as usize]);
  println!("wire_bytes_per_hs rx(server->client)={:.0} tx(client->server)={:.0}",rx.load(Ordering::Relaxed) as f64/n as f64,tx.load(Ordering::Relaxed) as f64/n as f64);
 }
 _=>{}}
}
