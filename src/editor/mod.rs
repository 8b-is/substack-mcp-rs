pub mod prosemirror;

use crate::editor::prosemirror::{DEFAULT_MAX_MARKDOWN_BYTES, markdown_to_prosemirror};
use crate::error::AppError;
use rmcp::schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Pure-Rust, zero-network Small Editor Model for Substack drafts.
///
/// Computes readability, structural cadence, AI-cliché heuristics, unsafe link sanitation,
/// and deterministic clean-ups in microseconds without leaving the local process.
pub struct SmallEditorModel;

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EditorialLint {
    pub line: usize,
    pub category: String,
    pub severity: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct EditorialReport {
    pub engine: String,
    pub title_candidate: Option<String>,
    pub subtitle_candidate: Option<String>,
    pub suggested_slug: String,
    pub word_count: usize,
    pub sentence_count: usize,
    pub estimated_read_minutes: u32,
    pub flesch_kincaid_grade: f64,
    pub prosemirror_blocks: usize,
    pub safe_links: usize,
    pub stripped_unsafe_links: Vec<String>,
    pub heading_outline: Vec<String>,
    pub ai_cliches_found: Vec<String>,
    pub long_paragraphs: usize,
    pub lints: Vec<EditorialLint>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PolishResult {
    pub engine: String,
    pub changes_applied: usize,
    pub polished_markdown: String,
    pub before: EditorialReport,
    pub after: EditorialReport,
}

const CLICHE_REPLACEMENTS: &[(&str, &str)] = &[
    ("in today's fast-paced world, ", ""),
    ("in today's fast-paced world", "today"),
    ("it is worth noting that ", ""),
    ("it's worth noting that ", ""),
    ("delve into", "examine"),
    ("a testament to", "evidence of"),
    ("game-changer", "shift"),
    ("double-edged sword", "trade-off"),
    ("unlock the power of", "use"),
    ("rich tapestry", "mix"),
];

impl SmallEditorModel {
    /// Analyzes a Markdown newsletter draft and produces structured telemetry and lints.
    pub fn analyze(markdown: &str) -> Result<EditorialReport, AppError> {
        let converted = markdown_to_prosemirror(markdown, DEFAULT_MAX_MARKDOWN_BYTES)?;
        let mut word_count = 0usize;
        let mut sentence_count = 0usize;
        let mut syllable_count = 0usize;
        let mut heading_outline = Vec::new();
        let mut title_candidate = None;
        let mut subtitle_candidate = None;
        let mut lints = Vec::new();
        let mut ai_cliches_found = BTreeSet::new();
        let mut in_code_fence = false;

        for (idx, raw_line) in markdown.lines().enumerate() {
            let line_no = idx + 1;
            let trimmed = raw_line.trim();
            if trimmed.starts_with("```") {
                in_code_fence = !in_code_fence;
                continue;
            }
            if in_code_fence || trimmed.is_empty() {
                continue;
            }

            if let Some(heading_text) = trimmed.strip_prefix("# ") {
                if title_candidate.is_none() {
                    title_candidate = Some(heading_text.trim().to_string());
                }
                heading_outline.push(trimmed.to_string());
            } else if trimmed.starts_with("## ") || trimmed.starts_with("### ") {
                heading_outline.push(trimmed.to_string());
            } else if subtitle_candidate.is_none()
                && !trimmed.starts_with('!')
                && !trimmed.starts_with('>')
                && !trimmed.starts_with("---")
            {
                let first = trimmed.trim_start_matches('*').trim_end_matches('*').trim();
                if first.len() >= 12 && first.len() <= 200 {
                    subtitle_candidate = Some(first.to_string());
                }
            }

            let lower = trimmed.to_ascii_lowercase();
            for &(phrase, replacement) in CLICHE_REPLACEMENTS {
                if lower.contains(phrase) {
                    ai_cliches_found.insert(phrase.to_string());
                    lints.push(EditorialLint {
                        line: line_no,
                        category: "style/ai-cliche".to_string(),
                        severity: "warning".to_string(),
                        message: if replacement.is_empty() {
                            format!("Consider removing filler phrase `{phrase}`.")
                        } else {
                            format!("Consider replacing cliché `{phrase}` with `{replacement}`.")
                        },
                    });
                }
            }

            for token in trimmed.split_whitespace() {
                let cleaned: String = token
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '\'' || *c == '-')
                    .collect();
                if !cleaned.is_empty() {
                    word_count += 1;
                    syllable_count += estimate_syllables(&cleaned);
                }
                if token.ends_with('.') || token.ends_with('!') || token.ends_with('?') {
                    sentence_count += 1;
                }
            }
        }

        let mut long_paragraphs = 0usize;
        for (p_idx, para) in markdown.split("\n\n").enumerate() {
            let p_trim = para.trim();
            if p_trim.starts_with("```") || p_trim.starts_with('|') {
                continue;
            }
            let p_words = p_trim.split_whitespace().count();
            if p_words > 120 {
                long_paragraphs += 1;
                lints.push(EditorialLint {
                    line: p_idx + 1,
                    category: "readability/paragraph-length".to_string(),
                    severity: "info".to_string(),
                    message: format!(
                        "Paragraph ~#{} has {p_words} words (>120); consider splitting for newsletter scanability.",
                        p_idx + 1
                    ),
                });
            }
        }

        for unsafe_uri in &converted.stripped_unsafe_links {
            lints.push(EditorialLint {
                line: 1,
                category: "security/unsafe-link".to_string(),
                severity: "high".to_string(),
                message: format!(
                    "Neutralized disallowed link/media URI `{unsafe_uri}` during ProseMirror compilation."
                ),
            });
        }

        let effective_sentences = sentence_count.max(1) as f64;
        let effective_words = word_count.max(1) as f64;
        let syllables = syllable_count.max(1) as f64;
        let fk_grade = (0.39 * (effective_words / effective_sentences)
            + 11.8 * (syllables / effective_words)
            - 15.59)
            .clamp(0.0, 24.0);
        let flesch_kincaid_grade = (fk_grade * 100.0).round() / 100.0;

        let estimated_read_minutes = u32::try_from(word_count.div_ceil(225))
            .unwrap_or(u32::MAX)
            .max(1);

        let slug_seed = title_candidate.as_deref().unwrap_or("untitled-draft");
        let suggested_slug = slugify(slug_seed);

        Ok(EditorialReport {
            engine: "builtin-small-editor-v1".to_string(),
            title_candidate,
            subtitle_candidate,
            suggested_slug,
            word_count,
            sentence_count,
            estimated_read_minutes,
            flesch_kincaid_grade,
            prosemirror_blocks: converted.block_count,
            safe_links: converted.link_count,
            stripped_unsafe_links: converted.stripped_unsafe_links,
            heading_outline,
            ai_cliches_found: ai_cliches_found.into_iter().collect(),
            long_paragraphs,
            lints,
        })
    }

    /// Runs deterministic, citation-preserving editorial hygiene outside code fences.
    pub fn deterministic_polish(markdown: &str) -> Result<PolishResult, AppError> {
        let before = Self::analyze(markdown)?;
        let mut out_lines = Vec::new();
        let mut in_fence = false;
        let mut changes_applied = 0usize;

        for raw_line in markdown.lines() {
            let trimmed_end = raw_line.trim_end();
            if trimmed_end.len() != raw_line.len() {
                changes_applied += 1;
            }
            let check_trim = trimmed_end.trim_start();
            if check_trim.starts_with("```") {
                in_fence = !in_fence;
                out_lines.push(trimmed_end.to_string());
                continue;
            }
            if in_fence {
                out_lines.push(raw_line.to_string());
                continue;
            }

            let mut line = trimmed_end.to_string();
            for &(phrase, replacement) in CLICHE_REPLACEMENTS {
                if let Some((next, count)) = replace_case_insensitive(&line, phrase, replacement) {
                    line = next;
                    changes_applied += count;
                }
            }
            out_lines.push(line);
        }

        let mut polished_markdown = out_lines.join("\n");
        if markdown.ends_with('\n') && !polished_markdown.ends_with('\n') {
            polished_markdown.push('\n');
        }
        let after = Self::analyze(&polished_markdown)?;

        Ok(PolishResult {
            engine: "builtin-small-editor-v1".to_string(),
            changes_applied,
            polished_markdown,
            before,
            after,
        })
    }
}

fn replace_case_insensitive(
    input: &str,
    needle: &str,
    replacement: &str,
) -> Option<(String, usize)> {
    let lower_in = input.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    if !lower_in.contains(&lower_needle) {
        return None;
    }
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;
    let mut count = 0usize;
    while let Some(rel) = lower_in[cursor..].find(&lower_needle) {
        let abs = cursor + rel;
        // Preserve UTF-8 char boundaries before slicing original string.
        if input.is_char_boundary(abs) && input.is_char_boundary(abs + lower_needle.len()) {
            out.push_str(&input[cursor..abs]);
            out.push_str(replacement);
            cursor = abs + lower_needle.len();
            count += 1;
        } else {
            break;
        }
    }
    out.push_str(&input[cursor..]);
    if count > 0 { Some((out, count)) } else { None }
}

fn estimate_syllables(word: &str) -> usize {
    let bytes: Vec<char> = word.to_ascii_lowercase().chars().collect();
    if bytes.len() <= 3 {
        return 1;
    }
    let is_vowel = |c: char| matches!(c, 'a' | 'e' | 'i' | 'o' | 'u' | 'y');
    let mut syllables = 0usize;
    let mut prev_vowel = false;
    for &c in &bytes {
        let v = is_vowel(c);
        if v && !prev_vowel {
            syllables += 1;
        }
        prev_vowel = v;
    }
    if bytes.ends_with(&['e']) && syllables > 1 {
        syllables -= 1;
    }
    syllables.max(1)
}

fn slugify(seed: &str) -> String {
    let mut slug = String::with_capacity(seed.len().min(64));
    let mut prev_dash = true;
    for ch in seed.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && slug.len() < 64 {
            slug.push('-');
            prev_dash = true;
        }
        if slug.len() >= 64 {
            break;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        "draft".to_string()
    } else {
        slug
    }
}
