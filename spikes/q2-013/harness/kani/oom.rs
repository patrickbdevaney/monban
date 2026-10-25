// q2-013 OOM exit-code control. The harness has a REAL failing assertion ("real bug") after a memory-heavy part.
// Under a low memory cap CBMC must die or report OOM, and Kani must then FAIL (non-zero exit), never print
// VERIFICATION:- SUCCESSFUL (the #4905 false pass).
const K: usize = 32;

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(33)]
fn oom_with_real_bug() {
    let mut a: [u64; K] = kani::any();
    let mut i = 0;
    while i < K {
        let mut j = 0;
        while j + 1 < K - i {
            if a[j] > a[j + 1] { a.swap(j, j + 1); }
            j += 1;
        }
        i += 1;
    }
    let mut k = 0;
    while k + 1 < K { assert!(a[k] <= a[k + 1]); k += 1; }
    let x: u8 = kani::any();
    assert!(x != 7, "real bug");
}
