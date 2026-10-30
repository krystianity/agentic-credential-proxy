//! A one-way drop box for the agent.
//!
//! Files placed in one directory on this machine can be listed and fetched, and
//! a fetched file is deleted once it has been delivered. Nothing travels the
//! other way: there is no upload, no write, no rename, no way to create a
//! directory. The agent's whole vocabulary here is "what is there" and "give me
//! that one".
//!
//! The containment rule is that a request names *one file directly in that
//! directory* and nothing else. A name is a single path segment -- `/`, `\`, a
//! leading dot and control characters are all refused -- and only plain files
//! are served, so a symlink pointing at `~/.ssh/id_rsa` is skipped by the
//! listing and refused by name. The directory itself is resolved once at
//! startup, so every request joins a checked name onto an already-real path.

use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use anyhow::{bail, Context, Result};
use axum::body::{Body, Bytes};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use futures_util::stream;
use tokio::io::AsyncReadExt;

use crate::proxy::{reject, RejectedWith};

/// Read size per chunk while streaming a file out.
const CHUNK: usize = 64 * 1024;

/// The longest name we will look at. The filesystem's own limit is 255 bytes,
/// so anything longer cannot name a real file anyway.
const MAX_NAME_BYTES: usize = 255;

pub struct FileStore {
    /// Fully resolved at startup. Because it is canonical, joining a
    /// single-segment name onto it can only ever address a direct child.
    root: PathBuf,

    /// Files being streamed right now, keyed by `dev:ino`. A file is delivered
    /// once, so a second request arriving mid-flight is refused rather than
    /// handed a body that is about to be deleted underneath it.
    ///
    /// Keyed by identity rather than by the name that was asked for, because
    /// this filesystem is case-insensitive: `ok.txt` and `OK.TXT` are two
    /// spellings of one file, and keying on the spelling let both of them
    /// through at once.
    in_flight: Mutex<HashSet<String>>,
}

impl FileStore {
    /// Resolves the shared directory once, at startup. A missing directory, a
    /// file where a directory was meant, or a path that cannot be resolved is a
    /// startup error in the launching terminal, not a surprise at request time.
    pub fn open(dir: &Path) -> Result<Arc<Self>> {
        let root = std::fs::canonicalize(dir).with_context(|| {
            format!(
                "[files] dir {} could not be resolved; create it first",
                dir.display()
            )
        })?;

        if !std::fs::metadata(&root)
            .with_context(|| format!("[files] dir {}", root.display()))?
            .is_dir()
        {
            bail!("[files] dir {} is not a directory", root.display());
        }

        Ok(Arc::new(FileStore {
            root,
            in_flight: Mutex::new(HashSet::new()),
        }))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A name the proxy is willing to look up: one path segment, no tricks.
///
/// `/` and `\` are refused outright, so nothing can address a parent, a sibling
/// directory or an absolute path, and a leading dot takes `.`, `..` and every
/// dotfile with it. `"` is refused so the name can go into a `Content-Disposition`
/// header without any quoting question, and control characters so it cannot
/// forge a header or a log line.
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && !name.starts_with('.')
        && !name.contains(['/', '\\', '"'])
        && !name.chars().any(char::is_control)
}

/// The listing, as the JSON body the agent receives.
///
/// Only entries this proxy would actually hand over are listed: plain files
/// with a valid name, directly in the directory. Anything else -- a
/// subdirectory, a symlink, a dotfile -- is counted in `skipped` rather than
/// shown, so the list never advertises something a fetch would then refuse.
pub async fn list(store: &FileStore) -> Result<serde_json::Value, RejectedWith> {
    let mut dir = tokio::fs::read_dir(store.root()).await.map_err(|e| {
        tracing::error!(error = %e, dir = %store.root().display(), "listing the file share failed");
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error",
            "could not read the shared directory",
        )
    })?;

    let mut files = Vec::new();
    let mut skipped = 0usize;

    loop {
        let entry = match dir.next_entry().await {
            Ok(Some(e)) => e,
            Ok(None) => break,
            Err(e) => {
                tracing::error!(error = %e, "reading a directory entry failed");
                return Err(reject(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "error",
                    "could not read the shared directory",
                ));
            }
        };

        let name = entry.file_name().to_string_lossy().into_owned();
        // file_type() comes from the directory read, so it does not follow
        // symlinks: a link to a file elsewhere is a symlink here, not a file.
        let is_plain_file = matches!(entry.file_type().await, Ok(t) if t.is_file());
        if !is_plain_file || !valid_name(&name) {
            skipped += 1;
            continue;
        }

        let Ok(meta) = entry.metadata().await else {
            skipped += 1;
            continue;
        };

        // Same rule as `serve`: a hard link is a name for a file that lives
        // elsewhere, so it is never offered.
        if meta.nlink() > 1 {
            skipped += 1;
            continue;
        }

        files.push(serde_json::json!({
            "name": name,
            "bytes": meta.len(),
            "modified_unix": meta
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs()),
        }));
    }

    // Stable order, so a diff between two listings means something changed.
    files.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));

    Ok(serde_json::json!({
        "files": files,
        "skipped": skipped,
        "note": "GET /files/<name> returns the file and deletes it. Only plain \
                 files directly in one directory are shared; subdirectories, \
                 symlinks and dotfiles are never listed or served. The count in \
                 `skipped` is entries passed over for that reason.",
    }))
}

/// Marks a file as in flight, and unmarks it when dropped.
struct Claim {
    store: Arc<FileStore>,
    /// `dev:ino` of the open file, not the name the request used.
    key: String,
}

impl Claim {
    fn take(store: &Arc<FileStore>, key: &str) -> Option<Claim> {
        let mut set = store
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !set.insert(key.to_string()) {
            return None;
        }
        Some(Claim {
            store: Arc::clone(store),
            key: key.to_string(),
        })
    }
}

impl Drop for Claim {
    fn drop(&mut self) {
        self.store
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&self.key);
    }
}

/// Everything the response body needs to finish sending a file and then make it
/// disappear. Held by the stream, so the claim is released when the stream ends
/// or the client walks away.
struct Streaming {
    file: tokio::fs::File,
    path: PathBuf,
    /// Only for the audit line; the claim is keyed on identity, not on this.
    name: String,
    /// Identity of the file we opened, so the delete cannot hit a different one
    /// that arrived under the same name in the meantime.
    dev: u64,
    ino: u64,
    /// Bytes still owed against the Content-Length we promised.
    remaining: u64,
    /// Set once the transfer has failed; the file is then left in place.
    aborted: bool,
    /// Never read: dropping it *is* the point. It goes after the delete below,
    /// so the file stays claimed until it is actually gone.
    #[allow(dead_code)]
    claim: Claim,
}

/// Where the delete actually happens.
///
/// It cannot hang off the end of the stream: hyper stops polling a body once it
/// has taken the bytes the `Content-Length` promised, so on a successful
/// transfer the "remaining == 0" arm below is never reached. The drop is the one
/// thing that runs either way -- after the response has been written for a
/// transfer that finished, and early for one the client abandoned, which is why
/// it is still conditional on having sent every byte.
impl Drop for Streaming {
    fn drop(&mut self) {
        if self.aborted || self.remaining != 0 {
            // Broken half way: leave the file in place so the agent can simply
            // ask again.
            return;
        }
        consume(self);
    }
}

/// Serve one file and consume it.
///
/// The delete happens at the *end* of the body, not the start: a transfer that
/// breaks half way leaves the file in place, so the agent can simply ask again.
/// The cost of that choice is the opposite race -- a client that receives every
/// byte and then dies still counts as delivered -- and the in-flight claim is
/// what stops two concurrent readers from both being told they own it.
pub async fn serve(store: &Arc<FileStore>, name: &str) -> Result<Response, RejectedWith> {
    if !valid_name(name) {
        let shown: String = name.chars().take(64).collect();
        return Err(reject(
            StatusCode::BAD_REQUEST,
            "deny-name",
            format!(
                "{shown:?} is not a shareable file name; it must name one file \
                 directly in the shared directory, with no '/' and no leading '.'"
            ),
        ));
    }

    let path = store.root().join(name);

    // Best effort, and not what the containment rests on: it narrows the
    // "someone swapped the shared directory itself for a symlink after startup"
    // window, which the O_NOFOLLOW open below cannot see because that flag only
    // applies to the last path component.
    match tokio::fs::canonicalize(&path).await {
        Ok(real) if real.parent() == Some(store.root()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(reject(
                StatusCode::NOT_FOUND,
                "deny-file",
                "no such file; GET /files for what is there",
            ))
        }
        _ => {
            tracing::warn!(name, "a file resolved outside the shared directory");
            return Err(reject(
                StatusCode::FORBIDDEN,
                "deny-file",
                "that name does not resolve inside the shared directory",
            ));
        }
    }

    // O_NOFOLLOW makes the open itself refuse a symlink, which is the whole
    // point: stat-then-open leaves a window where the name can become a symlink
    // between the two, and the open would then follow it. There is no window
    // here -- the kernel decides, once, on the name we hand it.
    //
    // O_NONBLOCK is what stops the open itself from being a denial of service.
    // Opening a fifo for reading blocks until someone opens the write end, and
    // because tokio::fs runs the open on a blocking thread, a fifo sitting in
    // the directory parks one of those threads for good -- the request never
    // answers and the thread never comes back. With O_NONBLOCK the open returns
    // at once and the "is it a plain file" check below is what refuses it. It
    // has no effect on reads of a regular file, which is all we go on to serve.
    let file = match tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(reject(
                StatusCode::FORBIDDEN,
                "deny-file",
                "that name is a symlink; only plain files are served",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(reject(
                StatusCode::NOT_FOUND,
                "deny-file",
                "no such file; GET /files for what is there",
            ))
        }
        Err(e) => {
            tracing::error!(error = %e, "opening a shared file failed");
            return Err(reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "error",
                "could not open the file",
            ));
        }
    };

    // From the open descriptor, not from the path: this is the file we are
    // actually sending, whatever the name points at by the time we finish. It
    // is also what rules out a directory, since opening one for reading
    // succeeds on macOS and only fails later, at the first read.
    let meta = match file.metadata().await {
        Ok(m) => m,
        Err(e) => {
            tracing::error!(error = %e, "stat of an open file failed");
            return Err(reject(
                StatusCode::INTERNAL_SERVER_ERROR,
                "error",
                "could not stat the file",
            ));
        }
    };
    if !meta.is_file() {
        return Err(reject(
            StatusCode::FORBIDDEN,
            "deny-file",
            "that name is not a plain file; only plain files are shared",
        ));
    }
    // A hard link is a second name for a file that lives somewhere else, and
    // nothing about it looks unusual from here: it is a plain file, it is a
    // direct child of the directory, and O_NOFOLLOW has no opinion about it.
    // Refusing more than one link is what keeps the contents of the directory
    // to things that are actually *in* the directory -- otherwise a single
    // `ln ~/.ssh/id_rsa drop/notes.txt` reads a file the share never pinned.
    if meta.nlink() > 1 {
        tracing::warn!(
            name,
            links = meta.nlink(),
            "refused a hard link in the shared directory"
        );
        return Err(reject(
            StatusCode::FORBIDDEN,
            "deny-file",
            "that name is a hard link to a file outside the share; copy it in \
             instead of linking it",
        ));
    }
    let len = meta.len();

    // Claimed here rather than before the open, so the key can be the file's
    // identity: two spellings of one name on a case-insensitive filesystem must
    // not both be handed the same file.
    let Some(claim) = Claim::take(store, &format!("{}:{}", meta.dev(), meta.ino())) else {
        return Err(reject(
            StatusCode::CONFLICT,
            "deny-busy",
            "that file is already being delivered to someone else",
        ));
    };

    let state = Streaming {
        file,
        path,
        name: name.to_string(),
        dev: meta.dev(),
        ino: meta.ino(),
        remaining: len,
        aborted: false,
        claim,
    };

    let body = Body::from_stream(stream::unfold(state, |mut st| async move {
        if st.aborted {
            return None;
        }
        if st.remaining == 0 {
            // Every byte we promised has gone out. Ending the stream drops
            // `st`, and that is what deletes the file and releases the claim --
            // this arm is only reached when hyper polls once more than it
            // needs to, so it must not be the only path to the delete.
            return None;
        }

        // Never read past the length we promised, so the body cannot outgrow
        // its Content-Length if the file is still being written into the
        // directory while we send it.
        let want = st.remaining.min(CHUNK as u64) as usize;
        let mut buf = vec![0u8; want];

        match st.file.read(&mut buf).await {
            Ok(0) => {
                // The file shrank under us. Fail the transfer rather than send
                // a short body, and leave the file alone.
                st.aborted = true;
                let e = std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "the file shrank while it was being sent",
                );
                Some((Err(e), st))
            }
            Ok(n) => {
                buf.truncate(n);
                st.remaining -= n as u64;
                Some((Ok(Bytes::from(buf)), st))
            }
            Err(e) => {
                tracing::error!(error = %e, "reading a shared file failed");
                st.aborted = true;
                Some((Err(e), st))
            }
        }
    }));

    let mut response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len);

    // Only for names that fit in a header as-is; a non-ASCII name is fine on
    // disk and in the listing, it just does not get this hint.
    if name.is_ascii() {
        if let Ok(v) = HeaderValue::try_from(format!("attachment; filename=\"{name}\"")) {
            response = response.header(header::CONTENT_DISPOSITION, v);
        }
    }

    response.body(body).map_err(|e| {
        tracing::error!(error = %e, "building a file response failed");
        reject(
            StatusCode::INTERNAL_SERVER_ERROR,
            "error",
            "could not build the response",
        )
    })
}

/// Delete the file we just finished sending -- if the name still refers to it.
///
/// Between the open and here, the name could have been replaced by a different
/// file. Deleting that one would destroy something the agent never received, so
/// identity is checked first and a mismatch is logged and left alone.
///
/// Synchronous because it is called from a `Drop`, which cannot await. One stat
/// and one unlink against a local directory is a fair thing to do inline; the
/// alternative is spawning onto a runtime that may not be there by then.
fn consume(st: &Streaming) {
    let name = &st.name;
    match std::fs::symlink_metadata(&st.path) {
        Ok(meta) if meta.dev() == st.dev && meta.ino() == st.ino => {
            match std::fs::remove_file(&st.path) {
                Ok(()) => tracing::info!(
                    target: "audit",
                    decision = "consumed",
                    provider = "files",
                    file = %name,
                    "file delivered and deleted"
                ),
                Err(e) => tracing::error!(
                    error = %e,
                    file = %name,
                    "file was delivered but could not be deleted; it is still there"
                ),
            }
        }
        Ok(_) => tracing::warn!(
            file = %name,
            "the name was replaced while the file was being sent; not deleting"
        ),
        Err(e) => tracing::warn!(error = %e, file = %name, "file vanished before it could be deleted"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_one_segment_and_nothing_clever() {
        for ok in ["report.pdf", "a b c.txt", "castle-64x64.png", "ünïcode.txt"] {
            assert!(valid_name(ok), "{ok:?} should be shareable");
        }

        for bad in [
            "",
            ".",
            "..",
            "../etc/passwd",
            "/etc/passwd",
            "sub/file.txt",
            "sub\\file.txt",
            ".hidden",
            ".ssh",
            "quote\".txt",
            "nul\0byte",
            "newline\nname",
        ] {
            assert!(!valid_name(bad), "{bad:?} must be refused");
        }

        // Longer than any real filename can be.
        assert!(!valid_name(&"a".repeat(256)));
        assert!(valid_name(&"a".repeat(255)));
    }

    /// A drop directory of its own, so the tests cannot tread on each other.
    fn fresh_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("acp-files-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The share behind a real listener. In-process routing polls a body to
    /// completion and opens files on the caller's thread, which is exactly what
    /// hides the failures these tests are about.
    async fn spawn_share(dir: &Path) -> std::net::SocketAddr {
        let store = FileStore::open(dir).unwrap();
        let app = axum::Router::new().route(
            "/files/{name}",
            axum::routing::get(move |axum::extract::Path(name): axum::extract::Path<String>| {
                let store = Arc::clone(&store);
                async move {
                    serve(&store, &name).await.unwrap_or_else(|e| {
                        Response::builder()
                            .status(e.status)
                            .body(Body::from(e.message))
                            .unwrap()
                    })
                }
            }),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    /// A hard link is a plain file, a direct child of the directory, and no
    /// symlink -- every check the share had would wave it through, while its
    /// contents live wherever the link points.
    #[tokio::test]
    async fn a_hard_link_out_of_the_share_is_refused() {
        let dir = fresh_dir("hardlink");
        let outside = dir.join("..").join(format!("acp-secret-{}", std::process::id()));
        std::fs::write(&outside, b"SECRET OUTSIDE THE SHARE").unwrap();
        std::fs::hard_link(&outside, dir.join("innocent.txt")).unwrap();

        let store = FileStore::open(&dir).unwrap();
        let Ok(listed) = list(&store).await else {
            panic!("listing the share failed");
        };
        assert_eq!(listed["files"].as_array().unwrap().len(), 0, "must not be offered");
        assert_eq!(listed["skipped"], 1);

        let addr = spawn_share(&dir).await;
        let response = reqwest::get(format!("http://{addr}/files/innocent.txt"))
            .await
            .unwrap();
        assert_eq!(response.status(), 403);
        let body = response.text().await.unwrap();
        assert!(!body.contains("SECRET"), "the link's target leaked: {body}");
        assert!(outside.exists(), "the target must be left alone");

        std::fs::remove_file(&outside).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Opening a fifo for reading blocks until a writer shows up. On tokio's
    /// blocking pool that parks a thread for good and the request never
    /// answers, so the open must not be allowed to wait.
    #[tokio::test]
    async fn a_fifo_cannot_park_the_open() {
        let dir = fresh_dir("fifo");
        let path = dir.join("fifo");
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0, "mkfifo failed");

        let addr = spawn_share(&dir).await;
        let response = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reqwest::get(format!("http://{addr}/files/fifo")),
        )
        .await
        .expect("the open blocked; a fifo in the share can wedge the proxy")
        .unwrap();
        assert_eq!(response.status(), 403);

        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A delivered file has to actually disappear.
    ///
    /// This one has to go over a real socket. Driving the router in-process
    /// polls the response body to completion, which hides the failure it is
    /// here to catch: hyper stops polling once it has taken `Content-Length`
    /// bytes, so anything hung off one-more-poll never runs and the file
    /// survives a fetch that looked perfectly successful to the agent.
    #[tokio::test]
    async fn a_delivered_file_is_consumed() {
        let dir = fresh_dir("consumed");

        // Small enough for one chunk, larger than one chunk, and empty: the
        // three ways the read loop can end.
        let cases: [(&str, Vec<u8>); 3] = [
            ("one.txt", b"hello drop\n".to_vec()),
            ("big.bin", vec![7u8; 3 * CHUNK + 11]),
            ("empty.txt", Vec::new()),
        ];
        for (name, body) in &cases {
            std::fs::write(dir.join(name), body).unwrap();
        }

        let addr = spawn_share(&dir).await;

        for (name, expected) in &cases {
            let url = format!("http://{addr}/files/{name}");
            let response = reqwest::get(&url).await.unwrap();
            assert_eq!(response.status(), 200, "{name}");
            assert_eq!(response.bytes().await.unwrap().as_ref(), &expected[..], "{name}");

            // The delete lands when the server drops the body, which is not
            // ordered against the client seeing the last byte -- so give it a
            // moment rather than racing it.
            let path = dir.join(name);
            for _ in 0..200 {
                if !path.exists() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(!path.exists(), "{name} was delivered but is still on disk");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
