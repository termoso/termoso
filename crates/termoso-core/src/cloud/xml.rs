//! Tiny DOM over `quick-xml` for the EC2 Query API responses. The payloads
//! are small (one page of instances) and deeply nested, so a tree is far
//! easier to walk than a streaming reader. Namespaces are ignored.

use quick_xml::Reader;
use quick_xml::events::Event;

/// An element with its text and children (attributes are not needed).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Node {
    /// Local element name.
    pub name: String,
    /// Concatenated direct text content, trimmed.
    pub text: String,
    /// Child elements in document order.
    pub children: Vec<Node>,
}

impl Node {
    /// First direct child called `name`.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All direct children called `name`.
    pub fn children(&self, name: &str) -> impl Iterator<Item = &Node> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Text of the first direct child called `name`, if non-empty.
    pub fn text_of(&self, name: &str) -> Option<&str> {
        self.child(name)
            .map(|c| c.text.as_str())
            .filter(|t| !t.is_empty())
    }

    /// Follow a path of child names.
    pub fn path(&self, names: &[&str]) -> Option<&Node> {
        names.iter().try_fold(self, |n, name| n.child(name))
    }
}

/// Parse a document into its root element.
pub fn parse(input: &str) -> Result<Node, String> {
    let mut reader = Reader::from_str(input);
    let mut stack: Vec<Node> = vec![Node::default()];
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(e) => stack.push(Node {
                name: local(e.local_name().as_ref()),
                ..Node::default()
            }),
            Event::Empty(e) => {
                let node = Node {
                    name: local(e.local_name().as_ref()),
                    ..Node::default()
                };
                stack.last_mut().expect("root").children.push(node);
            }
            Event::Text(t) => {
                let text = t.xml10_content();
                stack.last_mut().expect("root").text.push_str(&text);
            }
            Event::GeneralRef(r) => {
                let cur = stack.last_mut().expect("root");
                if let Some(c) = r.resolve_char_ref().map_err(|e| e.to_string())? {
                    cur.text.push(c);
                } else {
                    let name = r.into_inner();
                    match quick_xml::escape::resolve_predefined_entity(&name) {
                        Some(s) => cur.text.push_str(s),
                        None => return Err(format!("unknown entity &{name};")),
                    }
                }
            }
            Event::CData(c) => {
                stack
                    .last_mut()
                    .expect("root")
                    .text
                    .push_str(&c.into_inner());
            }
            Event::End(_) => {
                let mut node = stack.pop().ok_or("unbalanced xml")?;
                node.text = node.text.trim().to_string();
                stack
                    .last_mut()
                    .ok_or("unbalanced xml")?
                    .children
                    .push(node);
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if stack.len() != 1 {
        return Err("unterminated xml".into());
    }
    let mut root = stack.pop().expect("root");
    match root.children.len() {
        1 => Ok(root.children.pop().expect("one child")),
        0 => Err("empty document".into()),
        _ => Err("multiple root elements".into()),
    }
}

fn local(name: &str) -> String {
    name.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nested_and_unescapes() {
        let doc = r#"<?xml version="1.0"?>
<Root xmlns="http://example"><a><b>x &amp; y</b><b>z</b><empty/></a></Root>"#;
        let root = parse(doc).unwrap();
        assert_eq!(root.name, "Root");
        let a = root.child("a").unwrap();
        assert_eq!(a.text_of("b"), Some("x & y"));
        assert_eq!(a.children("b").count(), 2);
        assert!(a.child("empty").is_some());
        assert_eq!(root.path(&["a", "b"]).unwrap().text, "x & y");
    }

    #[test]
    fn rejects_broken() {
        assert!(parse("<a><b></a>").is_err());
        assert!(parse("").is_err());
    }
}
