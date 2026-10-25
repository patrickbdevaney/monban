// q2-013 representative Verus obligation (mirror F5 TBI-4/7: per-connection handler permits, permit held for the
// task lifetime). Ghost multiset `permits_out` of outstanding permit ids; invariant |permits_out| + available == S.
use vstd::prelude::*;
use vstd::multiset::Multiset;

verus! {

broadcast use vstd::multiset::group_multiset_axioms, vstd::multiset::group_multiset_properties;

pub const S: u64 = 100;     // handlers per connection (TBI-4)
pub const QMAX: u64 = 400;  // queued requests per connection (TBI-4)

pub struct Permit { pub id: u64 }

pub struct Ledger {
    pub available: u64,
    pub next_id: u64,
    pub queued: u64,
    pub permits_out: Ghost<Multiset<u64>>,
}

impl Ledger {
    pub open spec fn wf(&self) -> bool {
        &&& self.permits_out@.len() + self.available == S
        &&& self.queued <= QMAX
        // every outstanding id was issued before next_id (ids are unique and never forged)
        &&& forall|i: u64| self.permits_out@.contains(i) ==> i < self.next_id
        &&& forall|i: u64| self.permits_out@.count(i) <= 1
    }

    pub fn new() -> (l: Self)
        ensures l.wf(), l.available == S, l.permits_out@.len() == 0,
    {
        Ledger { available: S, next_id: 0, queued: 0, permits_out: Ghost(Multiset::empty()) }
    }

    pub fn acquire(&mut self) -> (r: Option<Permit>)
        requires old(self).wf(), old(self).next_id < u64::MAX,
        ensures
            final(self).wf(),
            final(self).next_id <= old(self).next_id + 1,
            final(self).queued == old(self).queued,
            match r {
                Some(p) => old(self).available > 0 && final(self).permits_out@ == old(self).permits_out@.insert(p.id)
                           && final(self).available == old(self).available - 1,
                None => old(self).available == 0 && final(self).permits_out@ == old(self).permits_out@
                        && final(self).available == 0,
            },
    {
        if self.available == 0 {
            return None;
        }
        let id = self.next_id;
        proof {
            assert(!self.permits_out@.contains(id));
        }
        self.available = self.available - 1;
        self.next_id = self.next_id + 1;
        self.permits_out = Ghost(self.permits_out@.insert(id));
        proof {
            assert forall|i: u64| self.permits_out@.contains(i) implies i < self.next_id by {
                if i != id { assert(old(self).permits_out@.contains(i)); }
            }
            assert forall|i: u64| self.permits_out@.count(i) <= 1 by {
                if i != id { assert(self.permits_out@.count(i) == old(self).permits_out@.count(i)); }
            }
        }
        Some(Permit { id })
    }

    /// Release consumes the permit (linear: a permit can be released once, cannot be forged).
    pub fn release(&mut self, p: Permit)
        requires old(self).wf(), old(self).permits_out@.contains(p.id),
        ensures
            final(self).wf(),
            final(self).available == old(self).available + 1,
            final(self).permits_out@ == old(self).permits_out@.remove(p.id),
            final(self).next_id == old(self).next_id,
    {
        self.available = self.available + 0;
        self.permits_out = Ghost(self.permits_out@.remove(p.id));
        proof {
            assert forall|i: u64| self.permits_out@.contains(i) implies i < self.next_id by {
                assert(old(self).permits_out@.contains(i));
            }
        }
    }

    /// Admission of a request into the per-connection queue: bounded by QMAX.
    pub fn enqueue(&mut self) -> (ok: bool)
        requires old(self).wf(),
        ensures final(self).wf(), ok <==> old(self).queued < QMAX, final(self).permits_out@ == old(self).permits_out@,
    {
        if self.queued < QMAX { self.queued = self.queued + 1; true } else { false }
    }

    pub fn dequeue_and_start(&mut self) -> (r: Option<Permit>)
        requires old(self).wf(), old(self).next_id < u64::MAX,
        ensures final(self).wf(), r.is_some() ==> final(self).queued == old(self).queued - 1,
    {
        if self.queued == 0 { return None; }
        let r = self.acquire();
        if r.is_some() { self.queued = self.queued - 1; }
        r
    }
}

/// Loop obligation: draining up to k acquisitions never exceeds S outstanding.
pub fn burst(l: &mut Ledger, k: u64) -> (got: u64)
    requires old(l).wf(), old(l).next_id + k < u64::MAX,
    ensures final(l).wf(), got <= S, final(l).permits_out@.len() == old(l).permits_out@.len() + got,
{
    let mut got: u64 = 0;
    let mut i: u64 = 0;
    while i < k
        invariant
            l.wf(), i <= k, got <= i, l.next_id <= old(l).next_id + i,
            old(l).next_id + k < u64::MAX,
            l.permits_out@.len() == old(l).permits_out@.len() + got,
            got <= S,
        decreases k - i,
    {
        match l.acquire() {
            Some(_p) => { got = got + 1; }
            None => {}
        }
        i = i + 1;
    }
    got
}

fn main() {}

} // verus!
