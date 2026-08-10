//! A TTL-aware DNS answer cache.
//!
//! Two rules drive the design, both of them things an earlier version got
//! wrong:
//!
//! 1. **A cached answer belongs to the name, not to the client that asked.**
//!    The cache stores only the resource records and the answer's own status.
//!    The response envelope — transaction ID, RD/CD bits, the EDNS OPT record
//!    — is rebuilt from the *current* request every time, so one client's
//!    DNSSEC or EDNS settings can never leak into another's answer.
//!
//! 2. **Never hand out a TTL the authority did not grant.** Each record keeps
//!    its own TTL and is counted down individually; a cache can only ever
//!    shorten a TTL, never extend one. `min_ttl` is therefore a
//!    *don't-bother-caching* threshold, not a floor to round up to.

use hickory_proto::op::{Edns, Message, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Everything about a request that can change the answer it deserves.
///
/// Class matters (an `IN` answer must not satisfy a `CH` query). The DNSSEC-OK
/// and checking-disabled bits matter because they change what the upstream
/// returns — a DO=1 answer carries RRSIGs that a DO=0 client did not ask for,
/// and a CD=1 answer may be one the resolver refused to validate.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Key {
    pub name: String,
    pub qtype: RecordType,
    pub qclass: DNSClass,
    pub dnssec_ok: bool,
    pub checking_disabled: bool,
}

impl Key {
    /// Derive the cache key from a request, so callers cannot forget a field.
    pub fn from_request(msg: &Message, name: &str) -> Option<Self> {
        let query = msg.queries.first()?;
        Some(Self {
            name: name.to_string(),
            qtype: query.query_type(),
            qclass: query.query_class(),
            dnssec_ok: msg.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
            checking_disabled: msg.metadata.checking_disabled,
        })
    }
}

/// The parts of an answer that are safe to reuse across clients.
struct Entry {
    answers: Vec<Record>,
    authorities: Vec<Record>,
    /// OPT is stripped before storing — it is per-transaction, never cacheable.
    additionals: Vec<Record>,
    response_code: ResponseCode,
    authoritative: bool,
    inserted: Instant,
    /// Governed by the shortest TTL in the answer: once any record would
    /// expire, the whole entry does.
    expires: Instant,
}

/// A cache hit, with every TTL already counted down. The caller wraps this in
/// a response envelope built from the current request.
pub struct CachedAnswer {
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    pub response_code: ResponseCode,
    pub authoritative: bool,
}

pub struct Cache {
    map: HashMap<Key, Entry>,
    max_entries: usize,
    /// Answers whose shortest TTL is below this are not cached at all. It never
    /// lengthens a TTL.
    min_ttl: u32,
    /// Upper bound on how long an entry is retained, regardless of TTL.
    max_ttl: u32,
    pub hits: u64,
    pub misses: u64,
}

impl Cache {
    pub fn new(max_entries: usize, min_ttl: u32, max_ttl: u32) -> Self {
        Self {
            map: HashMap::new(),
            max_entries: max_entries.max(1),
            min_ttl,
            max_ttl,
            hits: 0,
            misses: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Look up an answer, counting each record's own TTL down by the time it
    /// has spent in the cache.
    pub fn get(&mut self, key: &Key) -> Option<CachedAnswer> {
        let now = Instant::now();
        let entry = self.map.get(key)?;
        if entry.expires <= now {
            self.map.remove(key);
            self.misses += 1;
            return None;
        }

        let elapsed = now.duration_since(entry.inserted).as_secs() as u32;
        // Each record ages by the same wall-clock time but keeps its own TTL.
        let age = |records: &[Record]| -> Vec<Record> {
            records
                .iter()
                .map(|r| {
                    let mut r = r.clone();
                    r.ttl = r.ttl.saturating_sub(elapsed).max(1);
                    r
                })
                .collect()
        };

        let answer = CachedAnswer {
            answers: age(&entry.answers),
            authorities: age(&entry.authorities),
            additionals: age(&entry.additionals),
            response_code: entry.response_code,
            authoritative: entry.authoritative,
        };
        self.hits += 1;
        Some(answer)
    }

    /// Store an upstream answer, or decline to.
    ///
    /// Returns false when the answer is not cacheable: a transient failure, an
    /// answer with no TTL to reason about, or one shorter-lived than
    /// `min_ttl` is worth tracking.
    pub fn insert(&mut self, key: Key, message: &Message) -> bool {
        // Only successful answers and authoritative negatives. Caching a
        // SERVFAIL would keep a transient upstream blip alive.
        if !matches!(
            message.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return false;
        }

        // The entry can only live as long as its shortest-lived record.
        // Authority records matter here: for NXDOMAIN and NODATA the SOA
        // carries the negative-caching TTL and is the only TTL present.
        let Some(shortest) = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .map(|r| r.ttl)
            .min()
        else {
            // No answers and no SOA — nothing to base a lifetime on.
            return false;
        };

        // A zero TTL means "use once, do not cache", and anything under the
        // threshold is not worth an entry. Critically, neither case is rounded
        // *up* to min_ttl: that would serve a TTL the authority never granted.
        if shortest == 0 || shortest < self.min_ttl {
            return false;
        }
        let lifetime = shortest.min(self.max_ttl);

        if self.map.len() >= self.max_entries {
            self.evict();
        }

        let now = Instant::now();
        self.map.insert(
            key,
            Entry {
                answers: message.answers.clone(),
                authorities: message.authorities.clone(),
                // OPT is the client's EDNS envelope, not part of the answer.
                additionals: message
                    .additionals
                    .iter()
                    .filter(|r| r.record_type() != RecordType::OPT)
                    .cloned()
                    .collect(),
                response_code: message.metadata.response_code,
                authoritative: message.metadata.authoritative,
                inserted: now,
                expires: now + Duration::from_secs(lifetime as u64),
            },
        );
        true
    }

    /// Drop everything expired; if that frees nothing, drop the entries
    /// closest to expiry to make room.
    fn evict(&mut self) {
        let now = Instant::now();
        let before = self.map.len();
        self.map.retain(|_, e| e.expires > now);
        if self.map.len() < before {
            return;
        }

        // Nothing expired: shed the soonest-to-expire 10%.
        let target = self.map.len() / 10 + 1;
        let mut by_expiry: Vec<(Key, Instant)> = self
            .map
            .iter()
            .map(|(k, e)| (k.clone(), e.expires))
            .collect();
        by_expiry.sort_by_key(|(_, exp)| *exp);
        for (k, _) in by_expiry.into_iter().take(target) {
            self.map.remove(&k);
        }
    }

    pub fn sweep(&mut self) {
        let now = Instant::now();
        self.map.retain(|_, e| e.expires > now);
    }

    pub fn clear(&mut self) {
        self.map.clear();
    }
}

/// Build the OPT record a response should carry, given the request's own EDNS.
///
/// Returns `None` for a client that sent no OPT — such a client must not
/// receive one back.
pub fn response_edns(request: &Message, our_max_payload: u16) -> Option<Edns> {
    let req_edns = request.edns.as_ref()?;
    let mut edns = Edns::new();
    // Advertise what *we* can actually reassemble, not what the client hoped.
    edns.set_max_payload(req_edns.max_payload().min(our_max_payload));
    edns.set_version(0);
    edns.set_dnssec_ok(req_edns.flags().dnssec_ok);
    Some(edns)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{OpCode, Query};
    use hickory_proto::rr::rdata::{A, SOA};
    use hickory_proto::rr::{Name, RData};
    use std::net::Ipv4Addr;

    fn a_record(name: &str, ttl: u32, last: u8) -> Record {
        Record::from_rdata(
            Name::from_ascii(name).unwrap(),
            ttl,
            RData::A(A(Ipv4Addr::new(10, 0, 0, last))),
        )
    }

    fn soa_record(ttl: u32) -> Record {
        Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            ttl,
            RData::SOA(SOA::new(
                Name::from_ascii("ns.example.com.").unwrap(),
                Name::from_ascii("admin.example.com.").unwrap(),
                1,
                7200,
                3600,
                1_209_600,
                ttl,
            )),
        )
    }

    fn key(name: &str) -> Key {
        Key {
            name: name.into(),
            qtype: RecordType::A,
            qclass: DNSClass::IN,
            dnssec_ok: false,
            checking_disabled: false,
        }
    }

    fn response(code: ResponseCode) -> Message {
        let mut m = Message::response(0, OpCode::Query);
        m.metadata.response_code = code;
        m
    }

    #[test]
    fn each_record_keeps_its_own_ttl() {
        // The old cache flattened every record to the shortest TTL, so a
        // 3600s record came back claiming 60s.
        let mut c = Cache::new(10, 30, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("a.example.com.", 60, 1));
        msg.answers.push(a_record("b.example.com.", 3600, 2));

        assert!(c.insert(key("example.com"), &msg));
        let hit = c.get(&key("example.com")).expect("should hit");
        assert_eq!(hit.answers[0].ttl, 60);
        assert_eq!(hit.answers[1].ttl, 3600, "long TTL must not be flattened");
    }

    #[test]
    fn a_ttl_shorter_than_min_is_not_cached_rather_than_extended() {
        // The old cache rounded a 5s TTL up to min_ttl=30 and served it for
        // 30s — handing out a lifetime the authority never granted.
        let mut c = Cache::new(10, 30, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("short.example.com.", 5, 1));

        assert!(
            !c.insert(key("short.example.com"), &msg),
            "a sub-threshold TTL must be declined, never rounded up"
        );
        assert!(c.get(&key("short.example.com")).is_none());
    }

    #[test]
    fn max_ttl_can_shorten_an_entry_but_records_keep_their_ttl() {
        let mut c = Cache::new(10, 0, 60);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("long.example.com.", 100_000, 1));
        assert!(c.insert(key("long.example.com"), &msg));
        // We re-check sooner than the record claims, but we do not lie to the
        // client about what the authority said.
        let hit = c.get(&key("long.example.com")).unwrap();
        assert_eq!(hit.answers[0].ttl, 100_000);
    }

    #[test]
    fn dnssec_and_cd_answers_are_kept_apart() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut plain = response(ResponseCode::NoError);
        plain.answers.push(a_record("example.com.", 300, 1));

        let mut with_do = key("example.com");
        with_do.dnssec_ok = true;
        let mut with_cd = key("example.com");
        with_cd.checking_disabled = true;

        assert!(c.insert(key("example.com"), &plain));
        assert!(
            c.get(&with_do).is_none(),
            "a DO=0 answer must not satisfy a DO=1 query"
        );
        assert!(
            c.get(&with_cd).is_none(),
            "a CD=0 answer must not satisfy a CD=1 query"
        );
        assert!(c.get(&key("example.com")).is_some());
    }

    #[test]
    fn query_class_is_part_of_the_key() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("example.com.", 300, 1));
        assert!(c.insert(key("example.com"), &msg));

        let mut chaos = key("example.com");
        chaos.qclass = DNSClass::CH;
        assert!(c.get(&chaos).is_none(), "IN answer must not satisfy CH");
    }

    #[test]
    fn the_clients_opt_record_is_never_stored() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("example.com.", 300, 1));
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        msg.set_edns(edns);
        // set_edns also materialises an OPT into additionals on encode; make
        // the stored-additionals check explicit either way.
        msg.additionals.push(Record::from_rdata(
            Name::root(),
            0,
            RData::Update0(RecordType::OPT),
        ));

        assert!(c.insert(key("example.com"), &msg));
        let hit = c.get(&key("example.com")).unwrap();
        assert!(
            hit.additionals
                .iter()
                .all(|r| r.record_type() != RecordType::OPT),
            "OPT is per-transaction and must not be reused across clients"
        );
    }

    #[test]
    fn nxdomain_is_cached_off_the_soa_ttl() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut msg = response(ResponseCode::NXDomain);
        msg.authorities.push(soa_record(900));
        assert!(c.insert(key("nope.example.com"), &msg), "negative caching");

        let hit = c.get(&key("nope.example.com")).unwrap();
        assert_eq!(hit.response_code, ResponseCode::NXDomain);
        assert_eq!(hit.authorities[0].ttl, 900);
    }

    #[test]
    fn nodata_is_cached_off_the_soa_ttl() {
        // NOERROR with no answers but an SOA: a valid negative answer.
        let mut c = Cache::new(10, 0, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.authorities.push(soa_record(600));
        assert!(c.insert(key("nodata.example.com"), &msg));
        assert_eq!(
            c.get(&key("nodata.example.com")).unwrap().authorities[0].ttl,
            600
        );
    }

    #[test]
    fn servfail_and_empty_answers_are_not_cached() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut fail = response(ResponseCode::ServFail);
        fail.answers.push(a_record("example.com.", 300, 1));
        assert!(!c.insert(key("example.com"), &fail));

        // NOERROR with nothing at all to derive a lifetime from.
        assert!(!c.insert(key("bare.example.com"), &response(ResponseCode::NoError)));
    }

    #[test]
    fn zero_ttl_is_never_cached() {
        let mut c = Cache::new(10, 0, 86_400);
        let mut msg = response(ResponseCode::NoError);
        msg.answers.push(a_record("once.example.com.", 0, 1));
        assert!(!c.insert(key("once.example.com"), &msg));
    }

    #[test]
    fn key_from_request_captures_the_do_and_cd_bits() {
        let mut req = Message::query();
        req.metadata.checking_disabled = true;
        let mut q = Query::new();
        q.set_name(Name::from_ascii("example.com.").unwrap());
        q.set_query_type(RecordType::AAAA);
        req.add_query(q);
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        req.set_edns(edns);

        let k = Key::from_request(&req, "example.com").unwrap();
        assert_eq!(k.qtype, RecordType::AAAA);
        assert_eq!(k.qclass, DNSClass::IN);
        assert!(k.dnssec_ok);
        assert!(k.checking_disabled);
    }

    #[test]
    fn response_edns_never_invents_an_opt_for_a_client_without_one() {
        let bare = Message::query();
        assert!(response_edns(&bare, 1232).is_none());

        let mut with_edns = Message::query();
        let mut e = Edns::new();
        e.set_max_payload(65535);
        e.set_dnssec_ok(true);
        with_edns.set_edns(e);

        let out = response_edns(&with_edns, 1232).expect("client sent OPT");
        assert_eq!(out.max_payload(), 1232, "clamped to what we can reassemble");
        assert!(out.flags().dnssec_ok, "DO must be preserved");
    }
}
