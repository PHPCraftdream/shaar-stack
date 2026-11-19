//! The few XML reads that the answers of a UPnP gateway need. It is not a parser: the answers
//! are small, the names are fixed and the caller bounds the input.

/// The inner text of the first `name` element of `xml`, trimmed, with the five predefined
/// entities decoded. A namespace prefix on the tag is ignored.
pub(super) fn text(xml: &str, name: &str) -> Option<String> {
    element(xml, name, 0).map(|(inner, _)| decode(inner.trim()))
}

/// The inner slice of every `name` element of `xml`, in order. The elements must not nest.
pub(super) fn elements<'a>(xml: &'a str, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    let mut from = 0;
    std::iter::from_fn(move || {
        let (inner, next) = element(xml, name, from)?;
        from = next;
        Some(inner)
    })
}

/// The inner slice of the first `name` element that starts at or after `from`, and the offset
/// after its end tag. Every offset it handles is that of an ASCII `<` or `>`.
fn element<'a>(xml: &'a str, name: &str, from: usize) -> Option<(&'a str, usize)> {
    let mut at = from;
    let (inner_start, self_closed) = loop {
        let open = at + xml.get(at..)?.find('<')?;
        let close = open + xml[open..].find('>')?;
        let token = &xml[open + 1..close];
        at = close + 1;
        if token.starts_with(['/', '?', '!']) {
            continue;
        }
        if local_name(token) == name {
            break (at, token.ends_with('/'));
        }
    };
    if self_closed {
        return Some(("", inner_start));
    }
    let mut at = inner_start;
    loop {
        let open = at + xml.get(at..)?.find("</")?;
        let close = open + xml[open..].find('>')?;
        if local_name(&xml[open + 2..close]) == name {
            return Some((&xml[inner_start..open], close + 1));
        }
        at = close + 1;
    }
}

/// The element name of a tag's text without its prefix and attributes.
fn local_name(token: &str) -> &str {
    let end = token
        .find(|c: char| c.is_ascii_whitespace() || c == '/')
        .unwrap_or(token.len());
    let name = &token[..end];
    name.rsplit(':').next().unwrap_or(name)
}

fn decode(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    text.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_text_of_an_element_is_trimmed_and_its_entities_decoded() {
        let xml = "<a><controlURL>\n  /ctl?x=1&amp;y=2 \n</controlURL></a>";
        assert_eq!(text(xml, "controlURL").as_deref(), Some("/ctl?x=1&y=2"));
    }

    #[test]
    fn a_prefix_and_attributes_on_the_tag_are_ignored() {
        let xml = r#"<u:AddPortMappingResponse xmlns:u="x"><NewExternalIPAddress a="b">1.2.3.4</NewExternalIPAddress></u:AddPortMappingResponse>"#;
        assert_eq!(
            text(xml, "NewExternalIPAddress").as_deref(),
            Some("1.2.3.4")
        );
        assert_eq!(
            text(xml, "AddPortMappingResponse").as_deref(),
            Some(r#"<NewExternalIPAddress a="b">1.2.3.4</NewExternalIPAddress>"#)
        );
    }

    #[test]
    fn a_name_that_only_starts_like_the_wanted_one_does_not_match() {
        let xml = "<serviceList><service><serviceType>t</serviceType></service></serviceList>";
        assert_eq!(elements(xml, "service").count(), 1);
        assert_eq!(text(xml, "serviceTyp"), None);
    }

    #[test]
    fn every_element_of_a_name_is_returned_in_order() {
        let xml = "<l><s>one</s><x/><s>two</s><s/><s>three</s></l>";
        let all: Vec<_> = elements(xml, "s").collect();
        assert_eq!(all, ["one", "two", "", "three"]);
    }

    #[test]
    fn declarations_comments_and_missing_elements_give_nothing() {
        let xml = "<?xml version=\"1.0\"?><!-- c --><root></root>";
        assert_eq!(text(xml, "missing"), None);
        assert_eq!(text(xml, "root").as_deref(), Some(""));
    }

    #[test]
    fn broken_input_ends_without_a_panic() {
        for xml in [
            "", "<", "<a", "<a>", "<a>x</", "</a>", "<<>>", "<a>é</a", "é<a",
        ] {
            assert_eq!(elements(xml, "a").count(), 0, "{xml:?}");
            let _ = text(xml, "a");
        }
        assert_eq!(text("<a>é</a>", "a").as_deref(), Some("é"));
    }
}
