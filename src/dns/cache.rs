//! A small TTL-aware DNS answer cache.
//!
//! Stores decoded messages so we can rewrite the transaction ID and count
//! TTLs down on the way out, which is what a client expects from a resolver.

use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct Key {
    pub name: String,
    pub qtype: RecordType,
}

struct Entry {
    message: Message,
    inserted: Instant,
    expires: Instant,
    /// TTL the record set was stored with, so we can decrement correctly.
    original_ttl: u32,
}

pub struct Cache {
    map: HashMap<Key, Entry>,
    max_entries: usize,
    min_ttl: u32,
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

    /// Look up a cached answer, returning it with TTLs already adjusted for
    /// the time it has been sitting in the cache.
    pub fn get(&mut self, key: &Key) -> Option<Message> {
        let now = Instant::now();
        let entry = self.map.get(key)?;
        if entry.expires <= now {
            self.map.remove(key);
            self.misses += 1;
            return None;
        }

        let elapsed = now.duration_since(entry.inserted).as_secs() as u32;
        let remaining = entry.original_ttl.saturating_sub(elapsed).max(1);

        let mut msg = entry.message.clone();
        for rec in msg
            .answers
            .iter_mut()
            .chain(msg.authorities.iter_mut())
            .chain(msg.additionals.iter_mut())
        {
            rec.ttl = remaining;
        }
        self.hits += 1;
        Some(msg)
    }

    /// Store an upstream answer. Returns false if the message was not
    /// cacheable (no records, or a zero TTL).
    pub fn insert(&mut self, key: Key, message: &Message) -> bool {
        // Only cache successful answers and authoritative negatives; caching a
        // SERVFAIL would keep a transient upstream blip alive.
        use hickory_proto::op::ResponseCode;
        if !matches!(
            message.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ) {
            return false;
        }

        let min_record_ttl = message
            .answers
            .iter()
            .chain(message.authorities.iter())
            .map(|r| r.ttl)
            .min();

        let Some(ttl) = min_record_ttl else {
            return false;
        };
        if ttl == 0 {
            return false;
        }
        let ttl = ttl.clamp(self.min_ttl, self.max_ttl);

        if self.map.len() >= self.max_entries {
            self.evict();
        }

        let now = Instant::now();
        self.map.insert(
            key,
            Entry {
                message: message.clone(),
                inserted: now,
                expires: now + Duration::from_secs(ttl as u64),
                original_ttl: ttl,
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
