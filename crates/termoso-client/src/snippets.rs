//! Snippets and snippet packages. Rust stores, validates and expands
//! `{{variables}}` and normalises the text to type into a session; the UI
//! shells only render the tree and collect variable values.

use std::collections::{BTreeSet, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use termoso_core::model::{Host, HostSnippet, Snippet, SnippetPackage};
use termoso_core::store::Store;
use uuid::Uuid;

use crate::error::{ClientError, Result};

const MAX_SCRIPT_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetCard {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub script: String,
    pub package_id: Option<Uuid>,
    pub close_after_run: bool,
    pub sort_order: i32,
    /// `{{name}}` placeholders in the script, in order of first appearance.
    pub variables: Vec<String>,
    /// Hosts the snippet is configured to run on ("targets for execution").
    pub target_host_ids: Vec<Uuid>,
    pub updated_at: DateTime<Utc>,
    pub dirty: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnippetForm {
    pub id: Option<Uuid>,
    pub vault_id: Uuid,
    pub label: String,
    pub script: String,
    #[serde(default)]
    pub package_id: Option<Uuid>,
    #[serde(default)]
    pub close_after_run: bool,
    #[serde(default)]
    pub sort_order: i32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageNode {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub label: String,
    pub parent_id: Option<Uuid>,
    pub snippet_count: usize,
}

/// `{{name}}` placeholders, deduplicated, in first-appearance order.
pub fn variables(script: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    let mut rest = script;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let name = after[..end].trim();
                if !name.is_empty()
                    && !name.contains(['{', '}', '\n'])
                    && seen.insert(name.to_string())
                {
                    out.push(name.to_string());
                }
                rest = &after[end + 2..];
            }
            None => break,
        }
    }
    out
}

/// Substitute placeholders. Every variable must be provided.
pub fn expand(script: &str, vars: &HashMap<String, String>) -> Result<String> {
    let names = variables(script);
    let missing: BTreeSet<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| !vars.contains_key(*n))
        .collect();
    if !missing.is_empty() {
        return Err(ClientError::invalid(format!(
            "missing snippet variables: {}",
            missing.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let mut out = String::with_capacity(script.len());
    let mut rest = script;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        match after.find("}}") {
            Some(end) => {
                let name = after[..end].trim();
                match vars.get(name) {
                    Some(v) if names.iter().any(|n| n == name) => out.push_str(v),
                    _ => out.push_str(&rest[start..start + 2 + end + 2]),
                }
                rest = &after[end + 2..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    Ok(out)
}

fn card(e: termoso_core::model::Entity<Snippet>, targets: Vec<Uuid>) -> SnippetCard {
    SnippetCard {
        id: e.id,
        vault_id: e.vault_id,
        variables: variables(&e.data.script),
        target_host_ids: targets,
        label: e.data.label,
        script: e.data.script,
        package_id: e.data.package_id,
        close_after_run: e.data.close_after_run,
        sort_order: e.data.sort_order,
        updated_at: e.updated_at,
        dirty: e.dirty,
    }
}

/// Target hosts per snippet in execution order; bindings whose host is gone
/// are skipped.
fn targets_by_snippet(store: &Store, vault_id: Option<Uuid>) -> Result<HashMap<Uuid, Vec<Uuid>>> {
    let hosts: HashSet<Uuid> = store
        .list::<Host>(vault_id)?
        .into_iter()
        .map(|h| h.id)
        .collect();
    let mut bound = store.list::<HostSnippet>(vault_id)?;
    bound.sort_by_key(|b| b.data.sort_order);
    let mut out: HashMap<Uuid, Vec<Uuid>> = HashMap::new();
    for b in bound {
        if !hosts.contains(&b.data.host_id) {
            continue;
        }
        let list = out.entry(b.data.snippet_id).or_default();
        if !list.contains(&b.data.host_id) {
            list.push(b.data.host_id);
        }
    }
    Ok(out)
}

fn card_with_targets(store: &Store, id: Uuid) -> Result<SnippetCard> {
    let e = store.require::<Snippet>(id)?;
    let targets = targets_by_snippet(store, Some(e.vault_id))?
        .remove(&id)
        .unwrap_or_default();
    Ok(card(e, targets))
}

pub fn list(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<SnippetCard>> {
    let mut targets = targets_by_snippet(store, vault_id)?;
    let mut out: Vec<SnippetCard> = store
        .list::<Snippet>(vault_id)?
        .into_iter()
        .map(|e| {
            let t = targets.remove(&e.id).unwrap_or_default();
            card(e, t)
        })
        .collect();
    out.sort_by(|a, b| {
        a.sort_order
            .cmp(&b.sort_order)
            .then_with(|| a.label.to_lowercase().cmp(&b.label.to_lowercase()))
    });
    Ok(out)
}

fn validate(store: &Store, form: &SnippetForm) -> Result<Snippet> {
    let label = form.label.trim();
    if label.is_empty() {
        return Err(ClientError::invalid("snippet label is required"));
    }
    if form.script.trim().is_empty() {
        return Err(ClientError::invalid("snippet script is empty"));
    }
    if form.script.len() > MAX_SCRIPT_BYTES {
        return Err(ClientError::invalid("snippet script is too large"));
    }
    if let Some(p) = form.package_id {
        let pkg = store.require::<SnippetPackage>(p)?;
        if pkg.vault_id != form.vault_id {
            return Err(ClientError::invalid("package belongs to another vault"));
        }
    }
    Ok(Snippet {
        external_id: None,
        label: label.to_string(),
        script: form.script.clone(),
        package_id: form.package_id,
        close_after_run: form.close_after_run,
        sort_order: form.sort_order,
    })
}

pub fn save(store: &Store, form: &SnippetForm) -> Result<SnippetCard> {
    let data = validate(store, form)?;
    let id = match form.id {
        Some(id) => {
            store.require::<Snippet>(id)?;
            store.update(id, &data)?;
            id
        }
        None => store.insert(form.vault_id, &data)?,
    };
    card_with_targets(store, id)
}

/// Replace the snippet's target hosts. Duplicates collapse; order is kept.
pub fn set_targets(store: &Store, snippet_id: Uuid, host_ids: &[Uuid]) -> Result<SnippetCard> {
    let snippet = store.require::<Snippet>(snippet_id)?;
    let mut wanted: Vec<Uuid> = Vec::new();
    for &hid in host_ids {
        if wanted.contains(&hid) {
            continue;
        }
        let host = store.require::<Host>(hid)?;
        if host.vault_id != snippet.vault_id {
            return Err(ClientError::invalid("host belongs to another vault"));
        }
        wanted.push(hid);
    }
    for hs in store.list::<HostSnippet>(Some(snippet.vault_id))? {
        if hs.data.snippet_id == snippet_id {
            store.delete(hs.id)?;
        }
    }
    for (i, hid) in wanted.iter().enumerate() {
        store.insert(
            snippet.vault_id,
            &HostSnippet {
                host_id: *hid,
                snippet_id,
                sort_order: i as i32,
            },
        )?;
    }
    card_with_targets(store, snippet_id)
}

/// Delete a snippet and every host binding / startup reference to it.
pub fn delete(store: &Store, id: Uuid) -> Result<()> {
    let e = store.require::<Snippet>(id)?;
    for hs in store.list::<HostSnippet>(Some(e.vault_id))? {
        if hs.data.snippet_id == id {
            store.delete(hs.id)?;
        }
    }
    for mut host in store.list::<Host>(Some(e.vault_id))? {
        if host.data.startup_snippet_id == Some(id) {
            host.data.startup_snippet_id = None;
            store.update(host.id, &host.data)?;
        }
    }
    store.delete(id)?;
    Ok(())
}

// ───────────────────────────── packages ─────────────────────────────

pub fn packages(store: &Store, vault_id: Option<Uuid>) -> Result<Vec<PackageNode>> {
    let mut counts: HashMap<Uuid, usize> = HashMap::new();
    for s in store.list::<Snippet>(vault_id)? {
        if let Some(p) = s.data.package_id {
            *counts.entry(p).or_insert(0) += 1;
        }
    }
    let mut out: Vec<PackageNode> = store
        .list::<SnippetPackage>(vault_id)?
        .into_iter()
        .map(|p| PackageNode {
            id: p.id,
            vault_id: p.vault_id,
            snippet_count: counts.get(&p.id).copied().unwrap_or(0),
            label: p.data.label,
            parent_id: p.data.parent_id,
        })
        .collect();
    out.sort_by_key(|a| a.label.to_lowercase());
    Ok(out)
}

fn is_descendant(store: &Store, candidate: Uuid, ancestor: Uuid) -> Result<bool> {
    let mut cur = Some(candidate);
    let mut hops = 0;
    while let Some(id) = cur {
        if id == ancestor {
            return Ok(true);
        }
        hops += 1;
        if hops > 64 {
            return Err(ClientError::invalid("package tree is too deep"));
        }
        cur = store.require::<SnippetPackage>(id)?.data.parent_id;
    }
    Ok(false)
}

pub fn save_package(
    store: &Store,
    vault_id: Uuid,
    id: Option<Uuid>,
    label: &str,
    parent_id: Option<Uuid>,
) -> Result<PackageNode> {
    let label = label.trim();
    if label.is_empty() {
        return Err(ClientError::invalid("package label is required"));
    }
    if let Some(p) = parent_id {
        let parent = store.require::<SnippetPackage>(p)?;
        if parent.vault_id != vault_id {
            return Err(ClientError::invalid("parent belongs to another vault"));
        }
        if let Some(me) = id
            && is_descendant(store, p, me)?
        {
            return Err(ClientError::invalid(
                "a package cannot be moved into itself",
            ));
        }
    }
    let data = SnippetPackage {
        label: label.to_string(),
        parent_id,
    };
    let id = match id {
        Some(id) => {
            store.require::<SnippetPackage>(id)?;
            store.update(id, &data)?;
            id
        }
        None => store.insert(vault_id, &data)?,
    };
    packages(store, Some(vault_id))?
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| ClientError::not_found(format!("package {id}")))
}

/// Delete a package; its snippets and sub-packages move to the parent.
pub fn delete_package(store: &Store, id: Uuid) -> Result<()> {
    let pkg = store.require::<SnippetPackage>(id)?;
    let parent = pkg.data.parent_id;
    for mut s in store.list::<Snippet>(Some(pkg.vault_id))? {
        if s.data.package_id == Some(id) {
            s.data.package_id = parent;
            store.update(s.id, &s.data)?;
        }
    }
    for mut child in store.list::<SnippetPackage>(Some(pkg.vault_id))? {
        if child.data.parent_id == Some(id) {
            child.data.parent_id = parent;
            store.update(child.id, &child.data)?;
        }
    }
    store.delete(id)?;
    Ok(())
}

// ───────────────────────────── vaults ─────────────────────────────

/// Copy (or move) a snippet into `vault_id`, at the top level. Host targets
/// stay behind (hosts belong to the source vault); a startup reference from a
/// host in the source vault is cleared on move.
pub fn copy_to_vault(store: &Store, id: Uuid, vault_id: Uuid, mv: bool) -> Result<SnippetCard> {
    let e = store.require::<Snippet>(id)?;
    if e.vault_id == vault_id {
        return Err(ClientError::invalid("snippet is already in this vault"));
    }
    let new_id = store.insert(
        vault_id,
        &Snippet {
            package_id: None,
            ..e.data.clone()
        },
    )?;
    if mv {
        delete(store, id)?;
    }
    card_with_targets(store, new_id)
}

/// Copy (or move) a package with its whole subtree (sub-packages and
/// snippets) into `vault_id`, at the top level.
pub fn copy_package_to_vault(
    store: &Store,
    id: Uuid,
    vault_id: Uuid,
    mv: bool,
) -> Result<PackageNode> {
    let root = store.require::<SnippetPackage>(id)?;
    if root.vault_id == vault_id {
        return Err(ClientError::invalid("package is already in this vault"));
    }
    let all_pkgs = store.list::<SnippetPackage>(Some(root.vault_id))?;
    let all_snips = store.list::<Snippet>(Some(root.vault_id))?;

    // Breadth-first over the subtree so parents are created before children.
    let mut mapping: HashMap<Uuid, Uuid> = HashMap::new();
    let mut queue = vec![(root.id, None::<Uuid>)];
    while !queue.is_empty() {
        let mut next = Vec::new();
        for (src_id, new_parent) in queue {
            let src = all_pkgs
                .iter()
                .find(|p| p.id == src_id)
                .ok_or_else(|| ClientError::not_found(format!("package {src_id}")))?;
            let new_id = store.insert(
                vault_id,
                &SnippetPackage {
                    label: src.data.label.clone(),
                    parent_id: new_parent,
                },
            )?;
            mapping.insert(src_id, new_id);
            for child in all_pkgs.iter().filter(|p| p.data.parent_id == Some(src_id)) {
                if mapping.contains_key(&child.id) {
                    return Err(ClientError::invalid("package tree has a cycle"));
                }
                next.push((child.id, Some(new_id)));
            }
        }
        queue = next;
    }
    let moved_snippets: Vec<_> = all_snips
        .into_iter()
        .filter(|s| s.data.package_id.is_some_and(|p| mapping.contains_key(&p)))
        .collect();
    for s in &moved_snippets {
        store.insert(
            vault_id,
            &Snippet {
                package_id: s.data.package_id.and_then(|p| mapping.get(&p).copied()),
                ..s.data.clone()
            },
        )?;
    }
    if mv {
        for s in moved_snippets {
            delete(store, s.id)?;
        }
        for p in mapping.keys() {
            store.delete(*p)?;
        }
    }
    let new_root = mapping[&root.id];
    packages(store, Some(vault_id))?
        .into_iter()
        .find(|p| p.id == new_root)
        .ok_or_else(|| ClientError::not_found(format!("package {new_root}")))
}

/// Normalise line endings and make sure the last line is executed.
pub fn script_to_send(script: &str) -> String {
    let mut s = script.replace("\r\n", "\n");
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

/// Normalise line endings and drop the trailing newline so nothing runs yet.
pub fn script_to_paste(script: &str) -> String {
    let s = script.replace("\r\n", "\n");
    s.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use termoso_core::store::LocalVaultKind;
    use termoso_core::termoso_crypto::keys::SymmetricKey;
    use termoso_core::termoso_proto::vault::VaultRole;

    fn store() -> Store {
        Store::open_in_memory(SymmetricKey::generate()).expect("store")
    }

    #[test]
    fn variables_are_extracted_once_in_order() {
        assert_eq!(
            variables("ssh {{ user }}@{{host}} -p {{port}} && echo {{user}} {{ }} {{a{b}}"),
            vec!["user", "host", "port"]
        );
        assert!(variables("no vars {{unterminated").is_empty());
    }

    #[test]
    fn expand_requires_every_variable() {
        let mut vars = HashMap::new();
        vars.insert("user".to_string(), "root".to_string());
        assert!(expand("{{user}}@{{host}}", &vars).is_err());
        vars.insert("host".to_string(), "db".to_string());
        assert_eq!(expand("{{ user }}@{{host}}", &vars).unwrap(), "root@db");
        assert_eq!(expand("plain", &vars).unwrap(), "plain");
        assert_eq!(script_to_send("a\r\nb"), "a\nb\n");
        assert_eq!(script_to_send("a\n"), "a\n");
        assert_eq!(script_to_paste("a\r\nb\n"), "a\nb");
    }

    #[test]
    fn targets_are_replaced_deduplicated_and_pruned() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let host = |label: &str| {
            store
                .insert(
                    vault,
                    &Host {
                        label: label.into(),
                        address: label.into(),
                        ..Default::default()
                    },
                )
                .unwrap()
        };
        let (a, b, c) = (host("a"), host("b"), host("c"));
        let s = save(
            &store,
            &SnippetForm {
                id: None,
                vault_id: vault,
                label: "uptime".into(),
                script: "uptime".into(),
                package_id: None,
                close_after_run: false,
                sort_order: 0,
            },
        )
        .unwrap();
        assert!(s.target_host_ids.is_empty());

        let s = set_targets(&store, s.id, &[b, a, b, c]).unwrap();
        assert_eq!(s.target_host_ids, vec![b, a, c]);
        assert_eq!(
            list(&store, Some(vault)).unwrap()[0].target_host_ids,
            vec![b, a, c]
        );

        // Replacing keeps only the new set, in the given order.
        let s = set_targets(&store, s.id, &[c, a]).unwrap();
        assert_eq!(s.target_host_ids, vec![c, a]);
        assert_eq!(store.list::<HostSnippet>(Some(vault)).unwrap().len(), 2);

        // A deleted host silently drops out of the targets.
        crate::hosts::delete(&store, c).unwrap();
        assert_eq!(
            list(&store, Some(vault)).unwrap()[0].target_host_ids,
            vec![a]
        );
        assert_eq!(store.list::<HostSnippet>(Some(vault)).unwrap().len(), 1);

        // Hosts from another vault are rejected.
        let other = Uuid::new_v4();
        store
            .upsert_vault(
                other,
                LocalVaultKind::Personal,
                "other",
                None,
                VaultRole::Manager,
                Some(&SymmetricKey::generate()),
                1,
            )
            .unwrap();
        let foreign = store
            .insert(
                other,
                &Host {
                    label: "x".into(),
                    address: "x".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(set_targets(&store, s.id, &[foreign]).is_err());

        // Deleting the snippet removes its bindings.
        delete(&store, s.id).unwrap();
        assert!(store.list::<HostSnippet>(Some(vault)).unwrap().is_empty());
    }

    #[test]
    fn packages_and_snippets_lifecycle() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let root = save_package(&store, vault, None, "ops", None).unwrap();
        let child = save_package(&store, vault, None, "db", Some(root.id)).unwrap();
        assert!(save_package(&store, vault, Some(root.id), "ops", Some(child.id)).is_err());

        let s = save(
            &store,
            &SnippetForm {
                id: None,
                vault_id: vault,
                label: "restart".into(),
                script: "systemctl restart {{svc}}".into(),
                package_id: Some(child.id),
                close_after_run: true,
                sort_order: 0,
            },
        )
        .unwrap();
        assert_eq!(s.variables, vec!["svc"]);
        assert_eq!(packages(&store, Some(vault)).unwrap()[0].snippet_count, 1);
        assert!(
            save(
                &store,
                &SnippetForm {
                    id: None,
                    vault_id: vault,
                    label: "empty".into(),
                    script: "  ".into(),
                    package_id: None,
                    close_after_run: false,
                    sort_order: 0,
                },
            )
            .is_err()
        );

        // Deleting the child package lifts its snippet to the parent.
        delete_package(&store, child.id).unwrap();
        let s2 = list(&store, Some(vault)).unwrap();
        assert_eq!(s2.len(), 1);
        assert_eq!(s2[0].package_id, Some(root.id));

        // Host startup reference is cleared on snippet delete.
        let host_id = store
            .insert(
                vault,
                &Host {
                    label: "h".into(),
                    address: "h".into(),
                    startup_snippet_id: Some(s.id),
                    ..Default::default()
                },
            )
            .unwrap();
        delete(&store, s.id).unwrap();
        assert!(
            store
                .require::<Host>(host_id)
                .unwrap()
                .data
                .startup_snippet_id
                .is_none()
        );
        assert!(list(&store, Some(vault)).unwrap().is_empty());
    }

    fn team_vault(store: &Store, role: VaultRole) -> Uuid {
        let id = Uuid::new_v4();
        store
            .upsert_vault(
                id,
                LocalVaultKind::Team,
                "team",
                Some(Uuid::new_v4()),
                role,
                Some(&SymmetricKey::generate()),
                1,
            )
            .unwrap();
        id
    }

    fn snippet(store: &Store, vault: Uuid, label: &str, package_id: Option<Uuid>) -> SnippetCard {
        save(
            store,
            &SnippetForm {
                id: None,
                vault_id: vault,
                label: label.into(),
                script: format!("echo {label}"),
                package_id,
                close_after_run: false,
                sort_order: 0,
            },
        )
        .unwrap()
    }

    #[test]
    fn snippet_copy_and_move_between_vaults() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let team = team_vault(&store, VaultRole::Editor);
        let pkg = save_package(&store, vault, None, "ops", None).unwrap();
        let s = snippet(&store, vault, "restart", Some(pkg.id));
        let host = store
            .insert(
                vault,
                &Host {
                    label: "h".into(),
                    address: "h".into(),
                    ..Default::default()
                },
            )
            .unwrap();
        set_targets(&store, s.id, &[host]).unwrap();

        // Copy: lands at the top level of the other vault, without host bindings.
        let copied = copy_to_vault(&store, s.id, team, false).unwrap();
        assert_eq!(copied.vault_id, team);
        assert_eq!(copied.script, "echo restart");
        assert!(copied.package_id.is_none());
        assert!(copied.target_host_ids.is_empty());
        assert_eq!(list(&store, Some(vault)).unwrap().len(), 1);
        assert_eq!(store.list::<HostSnippet>(None).unwrap().len(), 1);
        assert!(copy_to_vault(&store, s.id, vault, false).is_err());

        // Move: source and its bindings are gone.
        let moved = copy_to_vault(&store, s.id, team, true).unwrap();
        assert_eq!(moved.vault_id, team);
        assert!(list(&store, Some(vault)).unwrap().is_empty());
        assert!(store.list::<HostSnippet>(None).unwrap().is_empty());
        assert_eq!(list(&store, Some(team)).unwrap().len(), 2);
    }

    #[test]
    fn package_subtree_copy_and_move_remap_parents() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let team = team_vault(&store, VaultRole::Manager);
        let root = save_package(&store, vault, None, "ops", None).unwrap();
        let child = save_package(&store, vault, None, "db", Some(root.id)).unwrap();
        let grandchild = save_package(&store, vault, None, "pg", Some(child.id)).unwrap();
        let sibling = save_package(&store, vault, None, "web", None).unwrap();
        snippet(&store, vault, "top", Some(root.id));
        snippet(&store, vault, "deep", Some(grandchild.id));
        snippet(&store, vault, "other", Some(sibling.id));
        snippet(&store, vault, "loose", None);

        let new_root = copy_package_to_vault(&store, root.id, team, false).unwrap();
        assert_eq!(new_root.vault_id, team);
        assert!(new_root.parent_id.is_none());
        let team_pkgs = packages(&store, Some(team)).unwrap();
        assert_eq!(team_pkgs.len(), 3);
        let by_label = |l: &str| team_pkgs.iter().find(|p| p.label == l).unwrap().clone();
        assert_eq!(by_label("db").parent_id, Some(new_root.id));
        assert_eq!(by_label("pg").parent_id, Some(by_label("db").id));
        let team_snips = list(&store, Some(team)).unwrap();
        assert_eq!(team_snips.len(), 2);
        assert_eq!(
            team_snips
                .iter()
                .find(|s| s.label == "deep")
                .unwrap()
                .package_id,
            Some(by_label("pg").id)
        );
        // Untouched: everything outside the subtree, and the source itself.
        assert_eq!(packages(&store, Some(vault)).unwrap().len(), 4);
        assert_eq!(list(&store, Some(vault)).unwrap().len(), 4);
        assert!(copy_package_to_vault(&store, root.id, vault, false).is_err());

        // Move removes the subtree and its snippets, leaving the rest alone.
        copy_package_to_vault(&store, root.id, team, true).unwrap();
        let left: Vec<String> = packages(&store, Some(vault))
            .unwrap()
            .into_iter()
            .map(|p| p.label)
            .collect();
        assert_eq!(left, vec!["web"]);
        let left: Vec<String> = list(&store, Some(vault))
            .unwrap()
            .into_iter()
            .map(|s| s.label)
            .collect();
        assert_eq!(left, vec!["loose", "other"]);
        assert_eq!(packages(&store, Some(team)).unwrap().len(), 6);
    }

    #[test]
    fn viewer_vault_is_read_only_for_snippets() {
        let store = store();
        let vault = store.local_vault().unwrap().id;
        let viewer = team_vault(&store, VaultRole::Viewer);
        let s = snippet(&store, vault, "restart", None);
        assert_eq!(
            copy_to_vault(&store, s.id, viewer, false).unwrap_err().kind,
            "vault_read_only"
        );
        assert_eq!(
            save_package(&store, viewer, None, "ops", None)
                .unwrap_err()
                .kind,
            "vault_read_only"
        );
        assert!(list(&store, Some(viewer)).unwrap().is_empty());
        assert!(packages(&store, Some(viewer)).unwrap().is_empty());
    }
}
