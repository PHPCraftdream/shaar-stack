"""Exact reversible edits for the locked DNS transport; no archive code execution."""


def replace(text, old, new):
    if text.count(old) != 1:
        raise ValueError("reviewed DNS source anchor changed")
    return text.replace(old, new)


CONSTRUCTOR = '''impl<T, R> Transport<T, R> {
    /// Uses a caller-owned resolver without constructing a runtime provider.
    /// Resolver task admission and joined shutdown remain the caller's responsibility.
    pub fn with_resolver(inner: T, resolver: R) -> Self {
        Self {
            inner: Arc::new(Mutex::new(inner)),
            resolver,
        }
    }
}

'''
ONE_OLD = '''                            let addr = addr.replace(i, |_| Some(ip)).expect("`i` is a valid index");
                            unresolved.push(addr);'''
MANY_OLD = '''                                let addr =
                                    addr.replace(i, |_| Some(ip)).expect("`i` is a valid index");
                                unresolved.push(addr);'''
ADDRS_OLD = '''                            let suffix = addr.iter().skip(i + 1).collect::<Multiaddr>();
                            let prefix = addr.iter().take(i).collect::<Multiaddr>();
                            let mut n = 0;
                            for a in addrs {
                                if a.ends_with(&suffix) {
                                    if n < MAX_TXT_RECORDS {
                                        n += 1;
                                        tracing::trace!(protocol=%name, resolved=%a);
                                        let addr =
                                            prefix.iter().chain(a.iter()).collect::<Multiaddr>();
                                        unresolved.push(addr);
                                    } else {
                                        tracing::debug!(
                                            resolved=%a,
                                            "Too many TXT records, dropping resolved"
                                        );
                                    }
                                }
                            }'''
TXT_OLD = '''                    Ok(txts) => {
                        let mut addrs = Vec::new();
                        for txt in txts
                            .answers()
                            .iter()
                            .filter_map(|record| match &record.data {
                                RData::TXT(txt) => Some(txt),
                                _ => None,
                            })
                        {
                            if let Some(chars) = txt.txt_data.first() {
                                match parse_dnsaddr_txt(chars) {
                                    Err(e) => {
                                        // Skip over seemingly invalid entries.
                                        tracing::debug!("Invalid TXT record: {:?}", e);
                                    }
                                    Ok(a) => {
                                        addrs.push(a);
                                    }
                                }
                            }
                        }
                        Ok(Resolved::Addrs(addrs))
                    }'''
PARSE_OLD = '''/// Parses a `<character-string>` of a `dnsaddr` TXT record.
fn parse_dnsaddr_txt(txt: &[u8]) -> io::Result<Multiaddr> {
    let s = str::from_utf8(txt).map_err(invalid_data)?;
    match s.strip_prefix("dnsaddr=") {
        None => Err(invalid_data("Missing `dnsaddr=` prefix.")),
        Some(a) => Ok(Multiaddr::try_from(a).map_err(invalid_data)?),
    }
}

'''

EDITS = [
    ('#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]',
     '#![forbid(unsafe_code)]\n#![cfg_attr(docsrs, feature(doc_cfg, doc_auto_cfg))]\n\nmod bounded_expansion;'),
    ('    str,\n', ''),
    ('impl<T, R> libp2p_core::Transport for Transport<T, R>',
     CONSTRUCTOR + 'impl<T, R> libp2p_core::Transport for Transport<T, R>'),
    ('            unresolved.push(addr.clone());', '''            if bounded_expansion::has_dns(&addr)
                && addr.as_ref().len() > bounded_expansion::MAX_ADDRESS_BYTES
            {
                return Err(Error::ResolveError(ResolveError::from("DNS address exceeds the byte budget")));
            }
            unresolved.push(addr);'''),
    ('                        dial_errors.push(Error::TooManyLookups);',
     '                        bounded_expansion::retain_error(&mut dial_errors, Error::TooManyLookups);'),
    ('                            dial_errors.push(e);',
     '                            bounded_expansion::retain_error(&mut dial_errors, e);'),
    ('                            dial_errors.push(err);',
     '                            bounded_expansion::retain_error(&mut dial_errors, err);'),
    ('\n' + ONE_OLD, '\n                            bounded_expansion::push_numeric(&mut unresolved, &addr, i, ip);'),
    ('\n' + MANY_OLD, '\n                                bounded_expansion::push_numeric(&mut unresolved, &addr, i, ip);'),
    (ADDRS_OLD, '                            bounded_expansion::push_txt(&mut unresolved, &addr, i, addrs);'),
    ("    Many(Vec<Protocol<'a>>),", "    Many(SmallVec<[Protocol<'a>; 4]>),"),
    ('    Addrs(Vec<Multiaddr>),', '    Addrs(Lookup),'),
    (TXT_OLD, '                    Ok(txts) => Ok(Resolved::Addrs(txts)),'),
    (PARSE_OLD, ''),
]
NUMERIC_OLD = '''                                .chain(ips)
                                .map(Protocol::from)'''
NUMERIC_NEW = '''                                .chain(ips)
                                .take(bounded_expansion::MAX_NUMERIC)
                                .map(Protocol::from)'''
EMPTY_OLD = '''                    let one = ips
                        .next()
                        .expect("If there are no results, `Err(NoRecordsFound)` is expected.");'''
EMPTY_NEW = '''                    let Some(one) = ips.next() else {
                        return Err(Error::ResolveError(ResolveError::from("No Matching Records Found")));
                    };'''


def transform(library):
    for old, new in EDITS:
        library = replace(library, old, new)
    for old, new in ((NUMERIC_OLD, NUMERIC_NEW), (EMPTY_OLD, EMPTY_NEW)):
        if library.count(old) != 3:
            raise ValueError("reviewed DNS numeric source anchor changed")
        library = library.replace(old, new)
    return library


def reverse(library):
    for old, new in ((NUMERIC_OLD, NUMERIC_NEW), (EMPTY_OLD, EMPTY_NEW)):
        if library.count(new) != 3:
            raise ValueError("reviewed DNS numeric source anchor changed")
        library = library.replace(new, old)
    for old, new in reversed(EDITS):
        if new:
            library = replace(library, new, old)
        elif old == PARSE_OLD:
            library = replace(library, 'fn invalid_data(', PARSE_OLD + 'fn invalid_data(')
        else:
            library = replace(library, '    pin::Pin,\n', '    pin::Pin,\n' + old)
    return library
