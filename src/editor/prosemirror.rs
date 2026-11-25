use crate::error::AppError;
use crate::security::validate_safe_link;
use pulldown_cmark::{CodeBlockKind, Event, HeadingLevel, Options, Parser, Tag, TagEnd};
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// Default maximum Markdown input size accepted by the ProseMirror compiler (1 MiB).
pub const DEFAULT_MAX_MARKDOWN_BYTES: usize = 1024 * 1024;

/// Canonical Substack ProseMirror root document.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ProseMirrorDoc {
    #[serde(rename = "type")]
    pub doc_type: String,
    pub content: Vec<PmNode>,
}

/// A ProseMirror AST node matching Substack's block/inline schema.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PmNode {
    Paragraph {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<PmNode>,
    },
    Heading {
        attrs: HeadingAttrs,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<PmNode>,
    },
    BulletList {
        content: Vec<PmNode>,
    },
    OrderedList {
        attrs: OrderedListAttrs,
        content: Vec<PmNode>,
    },
    ListItem {
        content: Vec<PmNode>,
    },
    Blockquote {
        content: Vec<PmNode>,
    },
    CodeBlock {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attrs: Option<CodeBlockAttrs>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        content: Vec<PmNode>,
    },
    HorizontalRule,
    HardBreak,
    Image {
        attrs: ImageAttrs,
    },
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        marks: Vec<PmMark>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct HeadingAttrs {
    pub level: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct OrderedListAttrs {
    pub start: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct CodeBlockAttrs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct ImageAttrs {
    pub src: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PmMark {
    Strong,
    Em,
    Code,
    Link { attrs: LinkAttrs },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub struct LinkAttrs {
    pub href: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConversionResult {
    pub doc: ProseMirrorDoc,
    pub block_count: usize,
    pub link_count: usize,
    pub stripped_unsafe_links: Vec<String>,
}

enum Container {
    Doc(Vec<PmNode>),
    Paragraph(Vec<PmNode>),
    Heading {
        level: u8,
        children: Vec<PmNode>,
    },
    BulletList(Vec<PmNode>),
    OrderedList {
        start: u64,
        items: Vec<PmNode>,
    },
    ListItem(Vec<PmNode>),
    Blockquote(Vec<PmNode>),
    CodeBlock {
        language: Option<String>,
        text: String,
    },
    Image {
        attrs: Option<ImageAttrs>,
        alt: String,
    },
}

fn push_node(stack: &mut [Container], node: PmNode) {
    let Some(top) = stack.last_mut() else {
        return;
    };
    match top {
        Container::Doc(v)
        | Container::Paragraph(v)
        | Container::Heading { children: v, .. }
        | Container::Blockquote(v) => v.push(node),
        Container::BulletList(items) | Container::OrderedList { items, .. } => {
            if matches!(node, PmNode::ListItem { .. }) {
                items.push(node);
            }
        }
        Container::ListItem(children) => match node {
            PmNode::Text { .. } | PmNode::HardBreak | PmNode::Image { .. } => {
                // Substack ProseMirror requires text inside a paragraph inside listItem.
                if let Some(PmNode::Paragraph { content }) = children.last_mut() {
                    content.push(node);
                } else {
                    children.push(PmNode::Paragraph {
                        content: vec![node],
                    });
                }
            }
            other => children.push(other),
        },
        Container::CodeBlock { text, .. } => {
            if let PmNode::Text { text: s, .. } = node {
                text.push_str(&s);
            }
        }
        Container::Image { alt, .. } => {
            if let PmNode::Text { text: s, .. } = node {
                alt.push_str(&s);
            }
        }
    }
}

fn push_inline_text(stack: &mut [Container], s: &str, active_marks: &[PmMark]) {
    if s.is_empty() {
        return;
    }
    if let Some(Container::CodeBlock { text, .. }) = stack.last_mut() {
        text.push_str(s);
        return;
    }
    if let Some(Container::Image { alt, .. }) = stack.last_mut() {
        alt.push_str(s);
        return;
    }
    if !matches!(
        stack.last(),
        Some(Container::Paragraph(_) | Container::Heading { .. } | Container::ListItem(_))
    ) {
        return;
    }
    push_node(
        stack,
        PmNode::Text {
            text: s.to_string(),
            marks: active_marks.to_vec(),
        },
    );
}

fn heading_to_u8(level: HeadingLevel) -> u8 {
    match level {
        HeadingLevel::H1 => 1,
        HeadingLevel::H2 => 2,
        HeadingLevel::H3 => 3,
        HeadingLevel::H4 => 4,
        HeadingLevel::H5 => 5,
        HeadingLevel::H6 => 6,
    }
}

/// Converts Markdown into validated, sanitized Substack ProseMirror JSON in a single pass.
pub fn markdown_to_prosemirror(
    markdown: &str,
    max_bytes: usize,
) -> Result<ConversionResult, AppError> {
    if markdown.len() > max_bytes {
        return Err(AppError::PayloadTooLarge { max_bytes });
    }

    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_STRIKETHROUGH);

    let parser = Parser::new_ext(markdown, opts);
    let mut stack: Vec<Container> = vec![Container::Doc(Vec::new())];
    let mut active_marks: Vec<PmMark> = Vec::new();
    let mut link_stack: Vec<bool> = Vec::new();
    let mut link_count = 0usize;
    let mut stripped_unsafe_links = Vec::new();

    for event in parser {
        match event {
            Event::Start(tag) => match tag {
                Tag::Paragraph => stack.push(Container::Paragraph(Vec::new())),
                Tag::Heading { level, .. } => stack.push(Container::Heading {
                    level: heading_to_u8(level),
                    children: Vec::new(),
                }),
                Tag::BlockQuote(_) => stack.push(Container::Blockquote(Vec::new())),
                Tag::List(None) => stack.push(Container::BulletList(Vec::new())),
                Tag::List(Some(start)) => stack.push(Container::OrderedList {
                    start,
                    items: Vec::new(),
                }),
                Tag::Item => stack.push(Container::ListItem(Vec::new())),
                Tag::CodeBlock(kind) => {
                    let language = match kind {
                        CodeBlockKind::Indented => None,
                        CodeBlockKind::Fenced(info) => {
                            let lang = info.split_whitespace().next().unwrap_or("");
                            if lang.is_empty() {
                                None
                            } else {
                                Some(lang.to_string())
                            }
                        }
                    };
                    stack.push(Container::CodeBlock {
                        language,
                        text: String::new(),
                    });
                }
                Tag::Strong => active_marks.push(PmMark::Strong),
                Tag::Emphasis => active_marks.push(PmMark::Em),
                Tag::Link {
                    dest_url, title, ..
                } => {
                    if let Ok(safe_href) = validate_safe_link(dest_url.as_ref()) {
                        link_count += 1;
                        let title_opt = if title.is_empty() {
                            None
                        } else {
                            Some(title.to_string())
                        };
                        active_marks.push(PmMark::Link {
                            attrs: LinkAttrs {
                                href: safe_href,
                                title: title_opt,
                            },
                        });
                        link_stack.push(true);
                    } else {
                        stripped_unsafe_links.push(dest_url.to_string());
                        link_stack.push(false);
                    }
                }
                Tag::Image {
                    dest_url, title, ..
                } => {
                    if let Ok(safe_src) = validate_safe_link(dest_url.as_ref()) {
                        let title_opt = if title.is_empty() {
                            None
                        } else {
                            Some(title.to_string())
                        };
                        stack.push(Container::Image {
                            attrs: Some(ImageAttrs {
                                src: safe_src,
                                alt: None,
                                title: title_opt,
                            }),
                            alt: String::new(),
                        });
                    } else {
                        stripped_unsafe_links.push(dest_url.to_string());
                        stack.push(Container::Image {
                            attrs: None,
                            alt: String::new(),
                        });
                    }
                }
                _ => {}
            },
            Event::End(tag_end) => match tag_end {
                TagEnd::Paragraph => {
                    if let Some(Container::Paragraph(content)) = stack.pop() {
                        push_node(&mut stack, PmNode::Paragraph { content });
                    }
                }
                TagEnd::Heading(_) => {
                    if let Some(Container::Heading { level, children }) = stack.pop() {
                        push_node(
                            &mut stack,
                            PmNode::Heading {
                                attrs: HeadingAttrs { level },
                                content: children,
                            },
                        );
                    }
                }
                TagEnd::BlockQuote(_) => {
                    if let Some(Container::Blockquote(content)) = stack.pop() {
                        push_node(&mut stack, PmNode::Blockquote { content });
                    }
                }
                TagEnd::List(is_ordered) => {
                    if is_ordered {
                        if let Some(Container::OrderedList { start, items }) = stack.pop() {
                            push_node(
                                &mut stack,
                                PmNode::OrderedList {
                                    attrs: OrderedListAttrs { start },
                                    content: items,
                                },
                            );
                        }
                    } else if let Some(Container::BulletList(content)) = stack.pop() {
                        push_node(&mut stack, PmNode::BulletList { content });
                    }
                }
                TagEnd::Item => {
                    if let Some(Container::ListItem(content)) = stack.pop() {
                        push_node(&mut stack, PmNode::ListItem { content });
                    }
                }
                TagEnd::CodeBlock => {
                    if let Some(Container::CodeBlock { language, text }) = stack.pop() {
                        let content = if text.is_empty() {
                            Vec::new()
                        } else {
                            vec![PmNode::Text {
                                text: text.trim_end_matches('\n').to_string(),
                                marks: Vec::new(),
                            }]
                        };
                        push_node(
                            &mut stack,
                            PmNode::CodeBlock {
                                attrs: language.map(|lang| CodeBlockAttrs {
                                    language: Some(lang),
                                }),
                                content,
                            },
                        );
                    }
                }
                TagEnd::Strong => {
                    if let Some(pos) = active_marks
                        .iter()
                        .rposition(|m| matches!(m, PmMark::Strong))
                    {
                        active_marks.remove(pos);
                    }
                }
                TagEnd::Emphasis => {
                    if let Some(pos) = active_marks.iter().rposition(|m| matches!(m, PmMark::Em)) {
                        active_marks.remove(pos);
                    }
                }
                TagEnd::Link => {
                    if link_stack.pop() == Some(true)
                        && let Some(pos) = active_marks
                            .iter()
                            .rposition(|m| matches!(m, PmMark::Link { .. }))
                    {
                        active_marks.remove(pos);
                    }
                }
                TagEnd::Image => {
                    if let Some(Container::Image { attrs, alt }) = stack.pop()
                        && let Some(mut image_attrs) = attrs
                    {
                        if !alt.is_empty() {
                            image_attrs.alt = Some(alt);
                        }
                        push_node(&mut stack, PmNode::Image { attrs: image_attrs });
                    }
                }
                _ => {}
            },
            Event::Text(text) => push_inline_text(&mut stack, text.as_ref(), &active_marks),
            Event::Code(code) => {
                // Substack ProseMirror schema prefers inline code mark isolated from incompatible marks.
                let code_marks = if let Some(link) = active_marks
                    .iter()
                    .find(|m| matches!(m, PmMark::Link { .. }))
                    .cloned()
                {
                    vec![PmMark::Code, link]
                } else {
                    vec![PmMark::Code]
                };
                push_inline_text(&mut stack, code.as_ref(), &code_marks);
            }
            Event::SoftBreak => push_inline_text(&mut stack, " ", &active_marks),
            Event::HardBreak => push_node(&mut stack, PmNode::HardBreak),
            Event::Rule => push_node(&mut stack, PmNode::HorizontalRule),
            // Raw HTML (Event::Html / Event::InlineHtml) and unhandled tags are intentionally ignored for strict XSS safety.
            _ => {}
        }
    }

    let Some(Container::Doc(mut content)) = stack.pop() else {
        return Err(AppError::ProseMirrorInvalid(
            "failed to finalize ProseMirror document stack".to_string(),
        ));
    };
    if content.is_empty() {
        content.push(PmNode::Paragraph {
            content: Vec::new(),
        });
    }
    let block_count = content.len();
    Ok(ConversionResult {
        doc: ProseMirrorDoc {
            doc_type: "doc".to_string(),
            content,
        },
        block_count,
        link_count,
        stripped_unsafe_links,
    })
}

/// Renders a Substack `ProseMirrorDoc` deterministically back into clean Markdown.
pub fn prosemirror_to_markdown(doc: &ProseMirrorDoc) -> String {
    let mut out = String::with_capacity(1024);
    for (idx, node) in doc.content.iter().enumerate() {
        if idx > 0 {
            out.push_str("\n\n");
        }
        render_block(node, &mut out, "");
    }
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn render_block(node: &PmNode, out: &mut String, indent: &str) {
    match node {
        PmNode::Paragraph { content } => {
            out.push_str(indent);
            render_inlines(content, out);
        }
        PmNode::Heading { attrs, content } => {
            let level = usize::from(attrs.level.clamp(1, 6));
            out.push_str(indent);
            for _ in 0..level {
                out.push('#');
            }
            out.push(' ');
            render_inlines(content, out);
        }
        PmNode::BulletList { content } => {
            for (idx, item) in content.iter().enumerate() {
                if idx > 0 {
                    out.push('\n');
                }
                render_list_item(item, out, indent, "- ");
            }
        }
        PmNode::OrderedList { attrs, content } => {
            for (idx, item) in content.iter().enumerate() {
                if idx > 0 {
                    out.push('\n');
                }
                let marker = format!("{}. ", attrs.start + idx as u64);
                render_list_item(item, out, indent, &marker);
            }
        }
        PmNode::ListItem { .. } => {
            render_list_item(node, out, indent, "- ");
        }
        PmNode::Blockquote { content } => {
            for (idx, inner) in content.iter().enumerate() {
                if idx > 0 {
                    out.push('\n');
                }
                let mut inner_buf = String::new();
                render_block(inner, &mut inner_buf, "");
                for (line_idx, line) in inner_buf.lines().enumerate() {
                    if line_idx > 0 {
                        out.push('\n');
                    }
                    let _ = write!(out, "{indent}> {line}");
                }
            }
        }
        PmNode::CodeBlock { attrs, content } => {
            let lang = attrs
                .as_ref()
                .and_then(|a| a.language.as_deref())
                .unwrap_or("");
            let _ = writeln!(out, "{indent}```{lang}");
            for inner in content {
                if let PmNode::Text { text, .. } = inner {
                    out.push_str(text);
                }
            }
            if !out.ends_with('\n') {
                out.push('\n');
            }
            let _ = write!(out, "{indent}```");
        }
        PmNode::HorizontalRule => {
            let _ = write!(out, "{indent}---");
        }
        PmNode::Image { attrs } => {
            let alt = attrs.alt.as_deref().unwrap_or("");
            let _ = write!(out, "{indent}![{alt}]({})", attrs.src);
        }
        PmNode::HardBreak | PmNode::Text { .. } => render_inlines(std::slice::from_ref(node), out),
    }
}

fn render_list_item(node: &PmNode, out: &mut String, indent: &str, marker: &str) {
    if let PmNode::ListItem { content } = node {
        for (idx, inner) in content.iter().enumerate() {
            if idx == 0 {
                out.push_str(indent);
                out.push_str(marker);
                match inner {
                    PmNode::Paragraph { content } => render_inlines(content, out),
                    other => render_block(other, out, ""),
                }
            } else {
                out.push('\n');
                let sub_indent = format!("{indent}  ");
                render_block(inner, out, &sub_indent);
            }
        }
    }
}

fn render_inlines(nodes: &[PmNode], out: &mut String) {
    for node in nodes {
        match node {
            PmNode::HardBreak => out.push_str("  \n"),
            PmNode::Image { attrs } => {
                let alt = attrs.alt.as_deref().unwrap_or("");
                let _ = write!(out, "![{alt}]({})", attrs.src);
            }
            PmNode::Text { text, marks } => {
                let has_code = marks.iter().any(|m| matches!(m, PmMark::Code));
                let has_strong = marks.iter().any(|m| matches!(m, PmMark::Strong));
                let has_em = marks.iter().any(|m| matches!(m, PmMark::Em));
                let link = marks.iter().find_map(|m| match m {
                    PmMark::Link { attrs } => Some(attrs),
                    _ => None,
                });

                let mut s = if has_code {
                    format!("`{text}`")
                } else {
                    text.clone()
                };
                if has_em {
                    s = format!("*{s}*");
                }
                if has_strong {
                    s = format!("**{s}**");
                }
                if let Some(l) = link {
                    s = format!("[{s}]({})", l.href);
                }
                out.push_str(&s);
            }
            other => render_block(other, out, ""),
        }
    }
}
