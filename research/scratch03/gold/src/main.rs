use std::num::NonZeroU32;
use std::str::FromStr;
fn main() {
    let p = rustls::crypto::aws_lc_rs::default_provider();
    let n_kx = p.kx_groups.len();
    let q = governor::Quota::per_second(NonZeroU32::new(10).unwrap());
    let rl = governor::RateLimiter::direct(q);
    let ok = rl.check().is_ok();
    let ps = cedar_policy::PolicySet::from_str("permit(principal, action, resource);").unwrap();
    let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(1).enable_all().build().unwrap();
    let r = rt.block_on(async {
        let s = hyper::service::service_fn(|_r: hyper::Request<hyper::body::Incoming>| async { Ok::<_, std::convert::Infallible>(hyper::Response::new(String::new())) });
        let _ = std::mem::size_of_val(&s);
        let b = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
        let _ = std::mem::size_of_val(&b);
        h2::Reason::NO_ERROR
    });
    let _ = std::marker::PhantomData::<tokio_rustls::TlsAcceptor>;
    println!("{} {} {} {:?} {:?}", n_kx, ok, ps.policies().count(), r, hyper::Version::HTTP_2);
}
