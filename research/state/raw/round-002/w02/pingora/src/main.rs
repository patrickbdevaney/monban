use async_trait::async_trait;
use pingora::apps::http_app::ServeHttp;
use pingora::protocols::http::ServerSession;
use pingora::proxy::{ProxyHttp,Session,http_proxy_service};
use pingora::prelude::*;
use pingora::services::listening::Service;
use http::Response;
pub struct Static;
#[async_trait]
impl ServeHttp for Static{
 async fn response(&self,_s:&mut ServerSession)->Response<Vec<u8>>{
  let b=b"hello aegis\n".to_vec();
  Response::builder().status(200).header("content-length",b.len()).body(b).unwrap()
 }
}
pub struct P;
#[async_trait]
impl ProxyHttp for P{
 type CTX=();
 fn new_ctx(&self){}
 async fn upstream_peer(&self,_s:&mut Session,_c:&mut ())->Result<Box<HttpPeer>>{
  Ok(Box::new(HttpPeer::new(("127.0.0.1",9000),false,"".to_string())))
 }
}
fn main(){
 let threads:usize=std::env::args().nth(1).and_then(|s|s.parse().ok()).unwrap_or(1);
 let mut conf=pingora::server::configuration::ServerConf::default();
 conf.threads=threads;
 let mut server=Server::new_with_opt_and_conf(None,conf);
 server.bootstrap();
 let mut st=Service::new("static".to_string(),pingora::apps::http_app::HttpServer::new_app(Static));
 st.add_tcp("0.0.0.0:18080");
 let mut pr=http_proxy_service(&server.configuration,P);
 pr.add_tcp("0.0.0.0:18081");
 server.add_service(st);server.add_service(pr);
 server.run_forever();
}
