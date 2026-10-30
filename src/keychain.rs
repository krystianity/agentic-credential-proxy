use anyhow::{bail, Context, Result};
use security_framework::passwords::{generic_password, PasswordOptions};

use crate::secret::Secret;

/// Reads one generic password out of the login keychain.
///
/// The Security framework call is synchronous and can block on an ACL prompt,
/// so it runs off the runtime rather than stalling a worker thread that other
/// requests are streaming on.
pub async fn read(service: &str, account: &str) -> Result<Secret> {
    let service = service.to_string();
    let account = account.to_string();

    tokio::task::spawn_blocking(move || {
        let options = PasswordOptions::new_generic_password(&service, &account);
        // The error carries an OSStatus, never the item's contents.
        let bytes = generic_password(options).with_context(|| {
            format!("no readable keychain item for service {service:?} account {account:?}")
        })?;
        if bytes.is_empty() {
            bail!("keychain item for service {service:?} account {account:?} is empty");
        }
        let value = String::from_utf8(bytes).with_context(|| {
            format!("keychain item for service {service:?} account {account:?} is not valid UTF-8")
        })?;
        // A trailing newline from `security add-generic-password -w "$(...)"` is
        // the classic cause of a 401 that looks like a wrong key.
        Ok(Secret::new(value.trim().to_string()))
    })
    .await
    .context("keychain read task failed")?
}
