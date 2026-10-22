//! Full-text repository search, backed by tantivy.
//!
//! The index lives in memory and is rebuilt from storage at startup; a self-hosted registry's
//! catalogue is small enough that this is quick and saves operators an index directory to back
//! up. Every change that affects what a repository is found by (push, tag deletion, metadata
//! edits, deletion, renames) re-indexes that repository.
//!
//! Besides names and metadata, a repository is found by what is inside it: platforms
//! (`amd64 alpine`, with aliases such as `x86_64` and `aarch64`), artifact kinds (`helm`,
//! `wasm`, `sbom`) and OCI image labels. Queries can also carry filters:
//! `arch:arm64 os:linux kind:helm tag:v1.2 topic:go ns:acme is:public`.
//!
//! With several registry instances, each holds its own index: built from storage at startup,
//! then kept current by the repository notifications every instance sends
//! ([`crate::database::notify`]): a repository's notification re-indexes it, a namespace
//! rename (or a listener that had to reconnect) rebuilds the whole index. A change made while
//! an instance missed notifications shows up there once that repository changes again, or at
//! the next restart.

use std::sync::Mutex;

use anyhow::Result;
use tantivy::collector::TopDocs;
use tantivy::query::{AllQuery, BooleanQuery, Occur, Query, QueryParser, TermQuery};
use tantivy::schema::{Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, Value, STORED, STRING};
use tantivy::tokenizer::{LowerCaser, SimpleTokenizer, TextAnalyzer};
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};

/// Re-index one repository after something it is found by changed. Search is a convenience,
/// so failures are logged rather than returned.
pub async fn reindex(storage: &kontainer_store::Storage, db: &crate::database::Db, public: &[String], index: &SearchIndex, repository: &str) {
    let result = match storage.list_tags(repository).await {
        Ok(tags) if tags.is_empty() && db.repo_meta(repository).await.ok().flatten().is_none() => index.remove(repository),
        Ok(_) => match repo_doc(storage, db, public, repository).await {
            Ok(doc) => index.upsert(&doc),
            Err(e) => Err(e),
        },
        Err(e) => Err(e),
    };
    if let Err(e) = result {
        tracing::warn!(repository, error = %e, "updating the search index");
    }
}

/// Rebuild the whole index from the registry tables. Returns the repositories indexed.
pub async fn rebuild(storage: &kontainer_store::Storage, db: &crate::database::Db, public: &[String], index: &SearchIndex) -> Result<usize> {
    let mut docs = vec![];
    for name in storage.list_repositories().await? {
        docs.push(repo_doc(storage, db, public, &name).await?);
    }
    index.rebuild(docs)
}

/// What a repository is searchable by.
#[derive(Debug, Clone, Default)]
pub struct RepoDoc {
    pub name: String,
    pub description: String,
    pub readme: String,
    pub topics: Vec<String>,
    pub tags: Vec<String>,
    /// `os/arch[/variant]` of every image in the recent tags.
    pub platforms: Vec<String>,
    /// Search keywords for the artifact kinds in the recent tags (`helm chart`, `wasm`, ...).
    pub kinds: Vec<String>,
    /// OCI image label values of the latest image (title, vendor, source, licenses, ...).
    pub labels: Vec<String>,
    pub public: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Hit {
    pub name: String,
    pub score: f32,
}

struct Fields {
    id: Field,
    namespace: Field,
    name: Field,
    description: Field,
    topics: Field,
    tags: Field,
    tag_exact: Field,
    platforms: Field,
    kinds: Field,
    labels: Field,
    readme: Field,
    visibility: Field,
}

pub struct SearchIndex {
    reader: IndexReader,
    writer: Mutex<IndexWriter>,
    f: Fields,
    /// Per-word exact matching across every field, boosted by field.
    exact: QueryParser,
    /// Prefix matching on word-like fields (for short words).
    prefix: QueryParser,
    /// Prefix matching that also forgives one typo in the name (for longer words).
    typo: QueryParser,
}

/// A query is cut to this many characters...
pub const MAX_QUERY_LEN: usize = 256;
/// ...and to this many words and filters: each becomes a (fuzzy) clause, so a pasted essay
/// would otherwise cost a search per word.
pub const MAX_QUERY_TERMS: usize = 16;

/// Run `f`, which blocks (an index commit, waiting for the writer), without stalling the async
/// worker thread it is called from: the runtime moves its other tasks elsewhere meanwhile.
fn blocking<R>(f: impl FnOnce() -> R) -> R {
    match tokio::runtime::Handle::try_current() {
        Ok(h) if h.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => tokio::task::block_in_place(f),
        _ => f(),
    }
}

/// Splits on anything that is not a letter or digit (`/`, `-`, `_`, `.`) and lowercases, so
/// `decube/images/ubuntu-base` is found by "ubuntu" or "base".
const WORDS: &str = "words";

/// Common alternative names for architectures, indexed alongside the canonical one.
fn arch_aliases(arch: &str) -> &'static [&'static str] {
    match arch {
        "amd64" => &["x86_64", "x64", "intel"],
        "arm64" => &["aarch64", "armv8", "arm"],
        "arm" => &["armhf", "armv7", "arm32"],
        "386" => &["i386", "i686", "x86"],
        "ppc64le" => &["power", "ppc64"],
        "s390x" => &["ibm", "mainframe"],
        "riscv64" => &["riscv"],
        "wasm" => &["webassembly"],
        _ => &[],
    }
}

/// Words that find a given artifact kind.
pub fn kind_keywords(kind: kontainer_core::artifact::ArtifactKind) -> &'static str {
    use kontainer_core::artifact::ArtifactKind::*;
    match kind {
        Image => "image container",
        Index => "image container multiarch multiplatform",
        HelmChart => "helm chart",
        Wasm => "wasm webassembly module",
        Sbom => "sbom bom cyclonedx spdx",
        Signature => "signature cosign",
        Attestation => "attestation provenance",
        Artifact => "artifact",
    }
}

fn words(s: &str) -> Vec<String> {
    s.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(str::to_lowercase).collect()
}

impl SearchIndex {
    pub fn new() -> Result<Self> {
        let mut sb = Schema::builder();
        let wordy = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer(WORDS).set_index_option(IndexRecordOption::WithFreqsAndPositions));
        let prose = TextOptions::default().set_indexing_options(TextFieldIndexing::default().set_tokenizer("en_stem").set_index_option(IndexRecordOption::WithFreqsAndPositions));
        let f = Fields {
            id: sb.add_text_field("id", STRING | STORED),
            namespace: sb.add_text_field("namespace", STRING),
            name: sb.add_text_field("name", wordy.clone()),
            description: sb.add_text_field("description", prose.clone()),
            topics: sb.add_text_field("topics", wordy.clone()),
            tags: sb.add_text_field("tags", wordy.clone()),
            tag_exact: sb.add_text_field("tag_exact", STRING),
            platforms: sb.add_text_field("platforms", wordy.clone()),
            kinds: sb.add_text_field("kinds", wordy.clone()),
            labels: sb.add_text_field("labels", prose.clone()),
            readme: sb.add_text_field("readme", prose),
            visibility: sb.add_text_field("visibility", STRING),
        };
        let index = Index::create_in_ram(sb.build());
        index.tokenizers().register(WORDS, TextAnalyzer::builder(SimpleTokenizer::default()).filter(LowerCaser).build());

        let mut exact = QueryParser::for_index(&index, vec![f.name, f.topics, f.description, f.platforms, f.kinds, f.tags, f.labels, f.readme]);
        for (field, boost) in [(f.name, 4.0), (f.topics, 2.5), (f.description, 2.0), (f.platforms, 1.5), (f.kinds, 1.5), (f.tags, 1.5), (f.labels, 1.0), (f.readme, 0.5)] {
            exact.set_field_boost(field, boost);
        }
        let fuzzy_fields = vec![f.name, f.topics, f.tags, f.platforms, f.kinds];
        let mut prefix = QueryParser::for_index(&index, fuzzy_fields.clone());
        let mut typo = QueryParser::for_index(&index, fuzzy_fields.clone());
        for field in &fuzzy_fields {
            prefix.set_field_fuzzy(*field, true, 0, false);
            typo.set_field_fuzzy(*field, true, if *field == f.name { 1 } else { 0 }, true);
        }

        let writer = index.writer_with_num_threads(1, 15_000_000)?;
        let reader = index.reader_builder().reload_policy(ReloadPolicy::Manual).try_into()?;
        Ok(Self { reader, writer: Mutex::new(writer), f, exact, prefix, typo })
    }

    fn document(&self, d: &RepoDoc) -> TantivyDocument {
        let f = &self.f;
        let mut doc = doc!(
            f.id => d.name.clone(),
            f.namespace => kontainer_core::names::namespace(&d.name).to_lowercase(),
            f.name => d.name.clone(),
            f.description => d.description.clone(),
            f.readme => d.readme.clone(),
            f.visibility => if d.public { "public" } else { "private" },
        );
        for t in &d.topics {
            doc.add_text(f.topics, t);
        }
        for t in &d.tags {
            doc.add_text(f.tags, t);
            doc.add_text(f.tag_exact, t.to_lowercase());
        }
        for p in &d.platforms {
            doc.add_text(f.platforms, p);
            for part in p.split('/') {
                for alias in arch_aliases(part) {
                    doc.add_text(f.platforms, alias);
                }
            }
            // `arm/v7` is also commonly written `armv7`.
            let parts: Vec<&str> = p.split('/').collect();
            if let [_, arch, variant] = parts.as_slice() {
                doc.add_text(f.platforms, format!("{arch}{variant}"));
            }
        }
        for k in &d.kinds {
            doc.add_text(f.kinds, k);
        }
        for l in &d.labels {
            doc.add_text(f.labels, l);
        }
        doc
    }

    fn commit(&self, w: &mut IndexWriter) -> Result<()> {
        w.commit()?;
        self.reader.reload()?;
        Ok(())
    }

    /// Replace the whole index. Blocks; fine to call from async code (see [`blocking`]).
    pub fn rebuild(&self, docs: impl IntoIterator<Item = RepoDoc>) -> Result<usize> {
        blocking(|| {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            w.delete_all_documents()?;
            let mut n = 0;
            for d in docs {
                w.add_document(self.document(&d))?;
                n += 1;
            }
            self.commit(&mut w)?;
            Ok(n)
        })
    }

    /// Add or replace one repository. Blocks; fine to call from async code.
    pub fn upsert(&self, d: &RepoDoc) -> Result<()> {
        blocking(|| {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            w.delete_term(Term::from_field_text(self.f.id, &d.name));
            w.add_document(self.document(d))?;
            self.commit(&mut w)
        })
    }

    /// Blocks; fine to call from async code.
    pub fn remove(&self, name: &str) -> Result<()> {
        blocking(|| {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            w.delete_term(Term::from_field_text(self.f.id, name));
            self.commit(&mut w)
        })
    }

    fn term(&self, field: Field, word: &str) -> Box<dyn Query> {
        Box::new(TermQuery::new(Term::from_field_text(field, word), IndexRecordOption::Basic))
    }

    /// A `key:value` filter as required clauses, or `None` if `key` is not a filter.
    fn filter(&self, key: &str, value: &str) -> Option<Vec<Box<dyn Query>>> {
        let f = &self.f;
        let value = value.to_lowercase();
        let on_words = |field: Field| words(&value).into_iter().map(|w| self.term(field, &w)).collect::<Vec<_>>();
        Some(match key {
            "arch" | "os" | "platform" => on_words(f.platforms),
            "kind" | "type" => on_words(f.kinds),
            "topic" => on_words(f.topics),
            "tag" => vec![self.term(f.tag_exact, &value)],
            "ns" | "namespace" | "org" | "user" => vec![self.term(f.namespace, &value)],
            "is" if value == "public" || value == "private" => vec![self.term(f.visibility, &value)],
            _ => return None,
        })
    }

    /// Ranked repository names. Each typed word must match: exactly in any field (names
    /// weigh most, then topics and description, then platforms, kinds, tags, labels and
    /// README), or as a prefix of a name/topic/tag/platform/kind word, forgiving one typo in
    /// names for longer words. `key:value` filters narrow the results. Only the first
    /// [`MAX_QUERY_TERMS`] words and filters of the first [`MAX_QUERY_LEN`] characters count.
    pub fn search(&self, text: &str, public_only: bool, limit: usize) -> Result<Vec<Hit>> {
        let text = match text.char_indices().nth(MAX_QUERY_LEN) {
            Some((end, _)) => &text[..end],
            None => text,
        };
        let mut must: Vec<Box<dyn Query>> = vec![];
        let mut has_text = false;
        'tokens: for token in text.split_whitespace() {
            if must.len() >= MAX_QUERY_TERMS {
                break;
            }
            if let Some((key, value)) = token.split_once(':') {
                if key.chars().all(|c| c.is_ascii_alphabetic()) {
                    if let Some(mut qs) = self.filter(&key.to_lowercase(), value) {
                        qs.truncate(MAX_QUERY_TERMS - must.len());
                        must.extend(qs);
                        continue;
                    }
                }
            }
            // A pasted image reference: drop the registry host (`registry.example.com/`,
            // `localhost:5000/`) so `host/zack/alpine:3.20` searches `zack alpine 3 20`.
            let token = match token.split_once('/') {
                Some((first, rest)) if first.contains('.') || first.contains(':') || first == "localhost" => rest,
                _ => token,
            };
            has_text = true;
            for w in words(token) {
                if must.len() >= MAX_QUERY_TERMS {
                    break 'tokens;
                }
                // Words are plain alphanumerics here, so the parsers cannot fail.
                let (exact, _) = self.exact.parse_query_lenient(&w);
                let (fuzzy, _) = if w.chars().count() >= 4 { self.typo.parse_query_lenient(&w) } else { self.prefix.parse_query_lenient(&w) };
                must.push(Box::new(BooleanQuery::new(vec![(Occur::Should, exact), (Occur::Should, fuzzy)])));
            }
        }
        if must.is_empty() {
            return Ok(vec![]);
        }
        if public_only {
            must.push(self.term(self.f.visibility, "public"));
        }
        // Filters alone (e.g. `arch:arm64`) list every match; score ties then break by name.
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = must.into_iter().map(|q| (Occur::Must, q)).collect();
        if !has_text {
            clauses.push((Occur::Should, Box::new(AllQuery)));
        }
        let query = BooleanQuery::new(clauses);
        let searcher = self.reader.searcher();
        let top = searcher.search(&query, &TopDocs::with_limit(limit).order_by_score())?;
        let mut hits = Vec::with_capacity(top.len());
        for (score, addr) in top {
            let doc: TantivyDocument = searcher.doc(addr)?;
            if let Some(name) = doc.get_first(self.f.id).and_then(|v| v.as_str()) {
                hits.push(Hit { name: name.to_string(), score });
            }
        }
        if !has_text {
            hits.sort_by(|a, b| a.name.cmp(&b.name));
        }
        Ok(hits)
    }

    pub fn len(&self) -> u64 {
        self.reader.searcher().num_docs()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How many of a repository's most recent tags are inspected for platforms and kinds.
const INSPECT_TAGS: usize = 20;

fn platform_label(p: &kontainer_core::manifest::Platform) -> String {
    match &p.variant {
        Some(v) => format!("{}/{}/{v}", p.os, p.architecture),
        None => format!("{}/{}", p.os, p.architecture),
    }
}

/// Gather what a repository is searchable by from storage and the catalogue, including the
/// platforms, artifact kinds and labels of its most recent tags.
pub async fn repo_doc(storage: &kontainer_store::Storage, db: &crate::database::Db, public_globs: &[String], name: &str) -> Result<RepoDoc> {
    use kontainer_core::manifest::{ImageConfig, Manifest};
    let meta = db.repo_meta(name).await?;
    let public = meta.as_ref().is_some_and(|m| m.visibility == crate::database::Visibility::Public) || kontainer_core::glob::any_matches(public_globs.iter(), name);
    let mut tags = storage.list_tags_resolved(name).await?;
    // cosign signature/attestation tags are noise for search.
    tags.retain(|t| kontainer_core::artifact::cosign_tag_target(&t.tag).is_none());
    tags.sort_by_key(|t| std::cmp::Reverse(t.pushed_at));

    let (mut platforms, mut kinds, mut labels) = (std::collections::BTreeSet::new(), std::collections::BTreeSet::new(), vec![]);
    let read_config = |digest: kontainer_core::digest::Digest| async move {
        match storage.blob_size(&digest).await? {
            Some(n) if n <= 1024 * 1024 => Ok::<_, anyhow::Error>(storage.blob_bytes(&digest).await?.and_then(|b| serde_json::from_slice::<ImageConfig>(&b).ok())),
            _ => Ok(None),
        }
    };
    for (i, t) in tags.iter().take(INSPECT_TAGS).enumerate() {
        let Some(bytes) = storage.manifest_bytes(name, &t.digest).await? else { continue };
        let Ok((m, media_type)) = Manifest::parse(&bytes, None) else { continue };
        kinds.insert(kind_keywords(kontainer_core::artifact::classify(&m, &media_type).kind));
        // The image whose labels describe the repository: the latest tag (first child of an index).
        let mut label_source = None;
        match &m {
            Manifest::Index(ix) => {
                for c in ix.manifests.iter().filter_map(|c| c.platform.as_ref().filter(|p| p.os != "unknown").map(|p| (c, p))) {
                    platforms.insert(platform_label(c.1));
                    if label_source.is_none() {
                        label_source = Some(c.0.digest.clone());
                    }
                }
            }
            Manifest::Image(im) => {
                if let Some(cfg) = read_config(im.config.digest.clone()).await? {
                    if let (Some(os), Some(arch)) = (&cfg.os, &cfg.architecture) {
                        platforms.insert(format!("{os}/{arch}"));
                    }
                    if i == 0 {
                        labels = cfg.config.and_then(|c| c.labels).map(|l| l.into_values().collect()).unwrap_or_default();
                    }
                }
            }
        }
        if i == 0 {
            if let Some(child) = label_source {
                if let Some(Ok((Manifest::Image(im), _))) = storage.manifest_bytes(name, &child).await?.map(|b| Manifest::parse(&b, None)) {
                    if let Some(cfg) = read_config(im.config.digest.clone()).await? {
                        labels = cfg.config.and_then(|c| c.labels).map(|l| l.into_values().collect()).unwrap_or_default();
                    }
                }
            }
        }
    }
    Ok(RepoDoc {
        name: name.to_string(),
        description: meta.as_ref().map(|m| m.description.clone()).unwrap_or_default(),
        readme: meta.as_ref().map(|m| m.readme.clone()).unwrap_or_default(),
        topics: meta.as_ref().map(|m| m.topic_list()).unwrap_or_default(),
        tags: tags.into_iter().map(|t| t.tag).collect(),
        platforms: platforms.into_iter().collect(),
        kinds: kinds.into_iter().map(str::to_string).collect(),
        labels,
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(name: &str, description: &str, platforms: &[&str], public: bool) -> RepoDoc {
        RepoDoc {
            name: name.into(),
            description: description.into(),
            platforms: platforms.iter().map(|s| s.to_string()).collect(),
            kinds: vec![kind_keywords(kontainer_core::artifact::ArtifactKind::Index).into()],
            tags: vec!["3.20".into(), "latest".into()],
            public,
            ..Default::default()
        }
    }

    #[test]
    fn ranks_and_filters() {
        let ix = SearchIndex::new().unwrap();
        ix.rebuild(vec![
            doc("decube/images/ubuntu", "Ubuntu 24.04 base image mirror", &["linux/amd64"], true),
            doc("zack/alpine", "Minimal base image", &["linux/amd64", "linux/arm64/v8", "linux/arm/v7"], true),
            doc("acme/api", "The billing API, written in Go", &["linux/arm64"], false),
            RepoDoc { name: "acme/charts/web".into(), kinds: vec![kind_keywords(kontainer_core::artifact::ArtifactKind::HelmChart).into()], labels: vec!["Acme Corp".into()], public: true, ..Default::default() },
        ])
        .unwrap();
        let names = |q: &str, public: bool| ix.search(q, public, 10).unwrap().into_iter().map(|h| h.name).collect::<Vec<_>>();
        assert_eq!(names("ubuntu", false), vec!["decube/images/ubuntu"]);
        assert_eq!(names("ubu", false), vec!["decube/images/ubuntu"], "prefix");
        assert_eq!(names("ubunto", false), vec!["decube/images/ubuntu"], "one typo");
        assert_eq!(names("decube/images", false), vec!["decube/images/ubuntu"], "paths are split into words");
        assert_eq!(names("billing", false), vec!["acme/api"], "description text");
        assert!(names("billing", true).is_empty(), "private repos excluded from public search");
        assert!(ix.search("\"unbalanced (", false, 10).is_ok(), "never errors on odd input");

        // What is inside: platforms, aliases, kinds and labels.
        assert_eq!(names("amd64 alpine", false), vec!["zack/alpine"]);
        assert_eq!(names("alpine amd64", false), vec!["zack/alpine"], "order does not matter");
        assert_eq!(names("amd64 alp", false), vec!["zack/alpine"], "prefix next to an exact word");
        assert_eq!(names("aarch64 alpine", false), vec!["zack/alpine"], "architecture alias");
        assert_eq!(names("armv7", false), vec!["zack/alpine"], "arm/v7 written armv7");
        assert!(names("s390x alpine", false).is_empty(), "every word must match");
        assert_eq!(names("helm", false), vec!["acme/charts/web"]);
        assert_eq!(names("acme corp", false), vec!["acme/charts/web"], "image labels");

        // Filters.
        assert_eq!(names("arch:arm64", false), vec!["acme/api", "zack/alpine"]);
        assert_eq!(names("arch:arm64 is:public", false), vec!["zack/alpine"]);
        assert_eq!(names("kind:helm", false), vec!["acme/charts/web"]);
        assert_eq!(names("ns:acme", false), vec!["acme/api", "acme/charts/web"]);
        assert_eq!(names("tag:3.20 base", false).len(), 2);
        assert_eq!(names("image ns:zack", false), vec!["zack/alpine"]);
        assert!(names("unknown:thing alpine", false).is_empty(), "unknown keys are plain words, and must match");
        assert_eq!(names("localhost:5555/zack/alpine:3.20", false), vec!["zack/alpine"], "pasted image reference");
        assert_eq!(names("registry.example.com/zack/alpine", false), vec!["zack/alpine"]);

        ix.upsert(&RepoDoc { name: "acme/api".into(), tags: vec!["v2-billing".into()], public: true, ..Default::default() }).unwrap();
        assert_eq!(names("billing", true), vec!["acme/api"], "re-indexed: now public, matched by tag");
        ix.remove("acme/api").unwrap();
        assert!(names("billing", false).is_empty());
        assert_eq!(ix.len(), 3);
    }

    #[test]
    fn long_queries_are_capped() {
        let ix = SearchIndex::new().unwrap();
        ix.rebuild(vec![doc("zack/alpine", "Minimal base image", &["linux/amd64"], true)]).unwrap();
        let names = |q: &str| ix.search(q, false, 10).unwrap().into_iter().map(|h| h.name).collect::<Vec<_>>();
        // Words past the cap are ignored, even ones that would match nothing.
        let capped = format!("{} nomatch", vec!["alpine"; MAX_QUERY_TERMS].join(" "));
        assert_eq!(names(&capped), vec!["zack/alpine"]);
        assert!(names(&format!("{} nomatch", vec!["alpine"; MAX_QUERY_TERMS - 1].join(" "))).is_empty());
        // So are characters past the length cap (here, the word after the spaces).
        let long = format!("alpine{}", " ".repeat(MAX_QUERY_LEN)) + "nomatch";
        assert_eq!(names(&long), vec!["zack/alpine"]);
        // Huge inputs and long filter values stay cheap.
        assert!(ix.search(&"x".repeat(1 << 20), false, 10).is_ok());
        assert!(ix.search(&format!("arch:{}", vec!["a"; 500].join("-")), false, 10).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn writes_from_async_code() {
        let ix = SearchIndex::new().unwrap();
        ix.upsert(&doc("zack/alpine", "Minimal base image", &["linux/amd64"], true)).unwrap();
        assert_eq!(ix.len(), 1);
        ix.remove("zack/alpine").unwrap();
        assert!(ix.is_empty());
    }
}
