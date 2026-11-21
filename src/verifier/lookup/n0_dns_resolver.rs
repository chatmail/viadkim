// cmdkim – implementation of the DKIM specification
// Copyright © 2022–2024 David Bürgin <dbuergin@gluet.ch>
// Copyright © 2026      Chatmail Developers
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

use super::LookupTxt;
use n0_dns_resolver::DnsResolver;
use std::{
    future::Future,
    io::{self, ErrorKind},
    pin::Pin,
};

impl LookupTxt for DnsResolver {
    type Answer = Box<dyn Iterator<Item = io::Result<Vec<u8>>>>;
    type Query<'a> = Pin<Box<dyn Future<Output = io::Result<Self::Answer>> + Send + 'a>>;

    fn lookup_txt(&self, domain: &str) -> Self::Query<'_> {
        let name = domain.to_owned();

        Box::pin(async move {
            let lookup = self.lookup_txt(name).await.map_err(io::Error::other)?;

            if lookup.is_empty() {
                return Err(io::Error::from(ErrorKind::NotFound));
            }

            let txts: Vec<Vec<u8>> = lookup
                .into_iter()
                .map(|txt| txt.to_string().into_bytes())
                .collect();

            let txts: Self::Answer = Box::new(txts.into_iter().map(Ok));

            Ok(txts)
        })
    }
}
