"""Reversible zero-capacity response storage and cache-only copy suppression."""

CONSTRUCTOR_OLD = '''            cache: Cache::builder()
                .max_capacity(capacity)
                .expire_after(EntryExpiry)
                .build(),'''
CONSTRUCTOR_NEW = '''            cache: (capacity != 0).then(|| {
                Cache::builder()
                    .max_capacity(capacity)
                    .expire_after(EntryExpiry)
                    .build()
            }),'''
ENABLED = '''    pub(crate) fn is_enabled(&self) -> bool {
        self.cache.is_some()
    }

'''
UPSERT_GUARD = '''        let Some(cache) = &self.cache else {
            return;
        };
'''
CNAME_GUARD = '''        if !self.cache.is_enabled() {
            return Ok(lookup);
        }
'''
POSITIVE_OLD = '''                let lookup = Lookup::new(message.clone(), valid_until);
                self.cache.insert(query, Ok(message), now);
                Ok(lookup)'''
POSITIVE_NEW = '''                if self.cache.is_enabled() {
                    let lookup = Lookup::new(message.clone(), valid_until);
                    self.cache.insert(query, Ok(message), now);
                    Ok(lookup)
                } else {
                    Ok(Lookup::new(message, valid_until))
                }'''
ERROR_OLD = '''                self.cache.insert(query, Err(err.clone()), now);'''
ERROR_NEW = '''                if self.cache.is_enabled() {
                    self.cache.insert(query, Err(err.clone()), now);
                }'''
EDITS = {
    "src/cache.rs": [
        ("    cache: Cache<Query, Entry>,", "    cache: Option<Cache<Query, Entry>>,"),
        (CONSTRUCTOR_OLD, CONSTRUCTOR_NEW),
        ("    /// Insert a response into the cache.\n", ENABLED + "    /// Insert a response into the cache.\n"),
        ("        let (ttl, result) = match result {", UPSERT_GUARD + "        let (ttl, result) = match result {"),
        ("            self.cache.entry(query).and_upsert_with", "            cache.entry(query).and_upsert_with"),
        ("            self.cache.insert(\n", "            cache.insert(\n"),
        ("        let entry = self.cache.get(query)?;", "        let entry = self.cache.as_ref()?.get(query)?;"),
        ("        self.cache.invalidate_all();", "        if let Some(cache) = &self.cache {\n            cache.invalidate_all();\n        }"),
        ("        self.cache.invalidate(query);", "        if let Some(cache) = &self.cache {\n            cache.invalidate(query);\n        }"),
        ("    pub(crate) fn entry_count(&self) -> u64 {\n", "    pub(crate) fn entry_count(&self) -> u64 {\n        let Some(cache) = &self.cache else {\n            return 0;\n        };\n"),
        ("            self.cache.run_pending_tasks();", "            cache.run_pending_tasks();"),
        ("        self.cache.entry_count()", "        cache.entry_count()"),
    ],
    "src/caching_client.rs": [
        ("    fn cname(&self, lookup: Lookup, query: Query) -> Result<Lookup, NetError> {\n",
         "    fn cname(&self, lookup: Lookup, query: Query) -> Result<Lookup, NetError> {\n" + CNAME_GUARD),
        (POSITIVE_OLD, POSITIVE_NEW),
        (ERROR_OLD, ERROR_NEW),
    ],
}


def test_access(text, reverse=False):
    boundary = "#[cfg(test)]\nmod tests {"
    if text.count(boundary) != 1:
        raise ValueError("reviewed cache test boundary changed")
    production, tests = text.split(boundary)
    old, new = "cache.cache.get(", "cache.cache.as_ref().unwrap().get("
    if reverse:
        old, new = new, old
    if old in production or tests.count(old) != 18:
        raise ValueError("reviewed cache private test access changed")
    return production + boundary + tests.replace(old, new)


def transform(files, replace):
    changed = {}
    for name, edits in EDITS.items():
        text = files[name].decode()
        for old, new in edits:
            text = replace(text, old, new)
        if name == "src/cache.rs":
            text = test_access(text)
        changed[name] = text.encode()
    return changed


def reverse(files, replace):
    restored = dict(files)
    for name, edits in EDITS.items():
        text = files[name].decode()
        if name == "src/cache.rs":
            text = test_access(text, reverse=True)
        for old, new in reversed(edits):
            text = replace(text, new, old)
        restored[name] = text.encode()
    return restored
