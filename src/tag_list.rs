// viadkim – implementation of the DKIM specification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
//
// This program is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program. If not, see <https://www.gnu.org/licenses/>.

//! Tag=value lists.
//!
//! See RFC 6376, section 3.2. Note that this implementation supports any
//! UTF-8-encoded tag values, in accordance with the informative implementation
//! note in that section.

use crate::parse::{strip_fws, strip_suffix};
use std::{
    collections::HashSet,
    error::Error,
    fmt::{self, Display, Formatter},
    str,
    vec::IntoIter,
};

/// An error that occurs when parsing a tag list.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum TagListError {
    /// A tag name appears more than once.
    DuplicateTag,
    /// The tag list is syntactically invalid.
    Syntax,
}

impl Display for TagListError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateTag => write!(f, "duplicate tag"),
            Self::Syntax => write!(f, "ill-formed tag list"),
        }
    }
}

impl Error for TagListError {}

/// A tag=value pair.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TagSpec<'a> {
    /// The tag name.
    pub name: &'a str,
    /// The tag value.
    pub value: &'a str,
}

/// A list of tag=value pairs with unique tag names.
///
/// This is a view type containing tags and values borrowed from a string.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TagList<'a>(Vec<TagSpec<'a>>);

impl<'a> TagList<'a> {
    /// Parses a tag=value list from a string.
    ///
    /// # Errors
    ///
    /// If the string is not a valid tag list, an error is returned.
    #[expect(clippy::should_implement_trait)]
    pub fn from_str(s: &'a str) -> Result<Self, TagListError> {
        match strip_tag_list(s) {
            Some(("", tags)) => {
                let mut names_seen = HashSet::new();
                if tags.iter().any(|tag| !names_seen.insert(tag.name)) {
                    return Err(TagListError::DuplicateTag);
                }
                Ok(Self(tags))
            }
            _ => Err(TagListError::Syntax),
        }
    }
}

impl<'a> AsRef<[TagSpec<'a>]> for TagList<'a> {
    fn as_ref(&self) -> &[TagSpec<'a>] {
        &self.0
    }
}

impl<'a> From<TagList<'a>> for Vec<TagSpec<'a>> {
    fn from(tag_list: TagList<'a>) -> Self {
        tag_list.0
    }
}

impl<'a> TryFrom<Vec<TagSpec<'a>>> for TagList<'a> {
    type Error = TagListError;

    fn try_from(tags: Vec<TagSpec<'a>>) -> Result<Self, Self::Error> {
        if tags.is_empty() {
            return Err(TagListError::Syntax);
        }

        let mut names_seen = HashSet::new();
        for tag in &tags {
            if !is_tag_name(tag.name) || !is_tag_value(tag.value) {
                return Err(TagListError::Syntax);
            }
            if !names_seen.insert(tag.name) {
                return Err(TagListError::DuplicateTag);
            }
        }

        Ok(Self(tags))
    }
}

impl<'a> IntoIterator for TagList<'a> {
    type Item = TagSpec<'a>;
    type IntoIter = IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

fn strip_tag_list(val: &str) -> Option<(&str, Vec<TagSpec<'_>>)> {
    let (mut s, t) = strip_tag_spec(val)?;

    let mut tags = vec![t];

    while let Some((snext, t)) = s.strip_prefix(';').and_then(strip_tag_spec) {
        s = snext;
        tags.push(t);
    }

    let s = s.strip_prefix(';').unwrap_or(s);

    Some((s, tags))
}

fn strip_tag_spec(val: &str) -> Option<(&str, TagSpec<'_>)> {
    let s = strip_fws(val).unwrap_or(val);

    let (s, name) = strip_tag_name(s)?;

    let s = strip_fws(s).unwrap_or(s);

    let s = s.strip_prefix('=')?;

    let s = strip_fws(s).unwrap_or(s);

    let (s, value) = match strip_tag_value(s) {
        Some((s, value)) => {
            let s = strip_fws(s).unwrap_or(s);
            (s, value)
        }
        None => (s, Default::default()),
    };

    Some((s, TagSpec { name, value }))
}

fn strip_tag_name(value: &str) -> Option<(&str, &str)> {
    let s = value
        .strip_prefix(is_alpha)?
        .trim_start_matches(is_alphanum);
    Some((s, strip_suffix(value, s)))
}

// Note erratum 5070 in ABNF
fn strip_tag_value(value: &str) -> Option<(&str, &str)> {
    fn strip_tval(s: &str) -> Option<&str> {
        s.strip_prefix(is_tval_char)
            .map(|s| s.trim_start_matches(is_tval_char))
    }

    let mut s = strip_tval(value)?;

    while let Some(snext) = strip_fws(s).and_then(strip_tval) {
        s = snext;
    }

    Some((s, strip_suffix(value, s)))
}

fn is_alpha(c: char) -> bool {
    c.is_ascii_alphabetic()
}

fn is_alphanum(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

fn is_tval_char(c: char) -> bool {
    // printable ASCII without ; plus any non-ASCII UTF-8
    matches!(c, '!'..=':' | '<'..='~') || !c.is_ascii()
}

/// Returns true if the string is a valid tag name, false otherwise.
pub fn is_tag_name(s: &str) -> bool {
    matches!(strip_tag_name(s), Some(("", _)))
}

/// Returns true if the string is a valid tag value, false otherwise.
pub fn is_tag_value(s: &str) -> bool {
    s.is_empty() || matches!(strip_tag_value(s), Some(("", _)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_list_from_str_ok() {
        let example = " v = 1 ; a=rsa-sha256;d=example.net; s=brisbane;
  c=simple; q=dns/txt; i=中文@eng.example.net;
  t=1117574938; x=1118006938;
  h=from:to:subject:date;
  z=From:foo@eng.example.net|To:joe@example.com|
   Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700
   ;
  bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=;
  b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR";
        let example = example.replace('\n', "\r\n");

        let tag_list = TagList::from_str(&example).unwrap();

        assert!(!tag_list.as_ref().is_empty());
    }
}
