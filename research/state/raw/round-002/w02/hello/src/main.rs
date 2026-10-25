use std::{convert::Infallible,sync::Arc};
use bytes::Bytes;
use http_body_util::Full;
use hyper::{service::service_fn,Request,Response};
use hyper_util::rt::{TokioExecutor,TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
async fn h(_r:Request<hyper::body::Incoming>)->Result<Response<Full<Bytes>>,Infallible>{Ok(Response::new(Full::new(Bytes::from_static(b"hello aegis\n"))))}
#[cfg(feature="h3")] fn extra(){ let c:Option<h3_quinn::Connection>=std::hint::black_box(None); let _=c; let e=quinn::Endpoint::server; std::hint::black_box(e); }
#[cfg(any(feature="wasm",feature="wasmjit"))] fn extra(){ let e=wasmtime::Engine::default(); let m=unsafe{wasmtime::Module::deserialize(&e,std::hint::black_box(&[0u8][..]))}; std::hint::black_box(m.is_ok()); }
#[cfg(feature="dlopen")] fn extra(){ let l=unsafe{libloading::Library::new("libx.so")}; std::hint::black_box(l.is_ok()); }
#[cfg(not(any(feature="h3",feature="wasm",feature="wasmjit",feature="dlopen")))] fn extra(){}
fn main(){ if std::env::var("AEGIS_X").is_ok(){extra();}
 let a:Vec<String>=std::env::args().collect();
 let addr=a.get(1).cloned().unwrap_or("0.0.0.0:8443".into());
 let tls=a.get(2).map(|s|s=="tls").unwrap_or(false);
 let threads:usize=a.get(3).and_then(|s|s.parse().ok()).unwrap_or(1);
 let rt=tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_io().build().unwrap();
 rt.block_on(async move{
  let acc=if tls{
   let _=rustls::crypto::aws_lc_rs::default_provider().install_default();
   let certs:Vec<_>=rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open("/w/cert.pem").unwrap())).collect::<Result<_,_>>().unwrap();
   let key=rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open("/w/key.pem").unwrap())).unwrap().unwrap();
   let mut cfg=rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs,key).unwrap();
   cfg.alpn_protocols=vec![b"h2".to_vec(),b"http/1.1".to_vec()];
   Some(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
  }else{None};
  let l=TcpListener::bind(&addr).await.unwrap();
  loop{
   let (s,_)=l.accept().await.unwrap();
   let acc=acc.clone();
   tokio::spawn(async move{
    let b=auto::Builder::new(TokioExecutor::new());
    match acc{
     Some(t)=>{if let Ok(s)=t.accept(s).await{let _=b.serve_connection(TokioIo::new(s),service_fn(h)).await;}}
     None=>{let _=b.serve_connection(TokioIo::new(s),service_fn(h)).await;}
    }
   });
  }
 });
}
