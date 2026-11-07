//! Peer introduction modules.
//!
//! A peer can describe its surface as a canonical Active Infinity module: the
//! provider names, the methods each grants, and the default budget ceilings.
//! The module is plain AINF bytes, so any language binding can validate it,
//! hash it and inspect it without a new wire format.
//!
//! An introduction never carries capability ids, arguments or secrets: it is a
//! description of shape, not authority.

use active_infinity::{encode, InfinityModule, Inode};

use crate::budget::Budget;
use crate::error::{Error, Result};

/// Longest name an introduction accepts for a peer, a provider or a method.
pub const MAX_NAME_BYTES: usize = 1024;

/// Build the canonical introduction module for a peer.
///
/// The encoding is canonical regardless of how the caller ordered anything: the
/// providers are sorted by name and then by their method lists, and each method
/// list is sorted and deduplicated, so the same surface always produces the same
/// bytes. That matters because a peer's fingerprint is derived from these bytes
/// — a `HashSet`-ordered plugin must not change the digest without changing the
/// surface.
pub fn build(peer: &str, providers: &[(String, Vec<String>)], budget: &Budget) -> Result<Vec<u8>> {
    check_name("peer", peer)?;
    let mut providers: Vec<(String, Vec<String>)> = providers.to_vec();
    for (provider, methods) in &mut providers {
        check_name("provider", provider)?;
        methods.sort();
        methods.dedup();
        for method in methods.iter() {
            check_name("method", method)?;
        }
    }
    // Two instances of one adapter are a documented configuration (a provider
    // per exchange context), so a duplicate name is not an error: the method
    // list breaks the tie, and two entries that tie are byte-identical, so
    // their order cannot change the output. Refusing duplicates made `intro()`
    // fail for the whole kernel (R-17 round 4, #4).
    providers.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));

    let mut module = InfinityModule::new();
    let peer_node = module.push(Inode::Str(peer.to_string()));

    let mut provider_nodes = Vec::with_capacity(providers.len());
    for (provider, methods) in &providers {
        let name_node = module.push(Inode::Str(provider.clone()));
        let method_nodes: Vec<_> = methods
            .iter()
            .map(|method| module.push(Inode::Str(method.clone())))
            .collect();
        let methods_node = module.push(Inode::Array {
            elements: method_nodes,
        });
        let fields = vec![
            ("methods".to_string(), methods_node),
            ("name".to_string(), name_node),
        ];
        provider_nodes.push(module.push(Inode::Table { fields }));
    }
    let providers_node = module.push(Inode::Array {
        elements: provider_nodes,
    });

    // A `u64` ceiling above `i64::MAX` would wrap to a negative module
    // integer: the introduction would advertise a budget nobody can honour.
    let ceiling = |value: u64| -> Result<i64> {
        i64::try_from(value)
            .map_err(|_| Error::InvalidArgument("a budget ceiling does not fit the module integer"))
    };
    let budget_fields = vec![
        (
            "max_array_len".to_string(),
            module.push(Inode::Int(ceiling(budget.max_array_len)?)),
        ),
        (
            "max_bytes".to_string(),
            module.push(Inode::Int(ceiling(budget.max_bytes)?)),
        ),
        (
            "max_calls".to_string(),
            module.push(Inode::Int(ceiling(budget.max_calls)?)),
        ),
        (
            "max_depth".to_string(),
            module.push(Inode::Int(ceiling(budget.max_depth)?)),
        ),
        (
            "max_nodes".to_string(),
            module.push(Inode::Int(ceiling(budget.max_nodes)?)),
        ),
        (
            "max_value_size".to_string(),
            module.push(Inode::Int(ceiling(budget.max_value_size)?)),
        ),
        (
            "max_wall_ms".to_string(),
            module.push(Inode::Int(ceiling(budget.max_wall_ms)?)),
        ),
    ];
    let budget_node = module.push(Inode::Table {
        fields: budget_fields,
    });

    let root = module.push(Inode::Table {
        fields: vec![
            ("default_budget".to_string(), budget_node),
            ("peer".to_string(), peer_node),
            ("providers".to_string(), providers_node),
        ],
    });
    module.set_root(Some(root));
    encode(&module).map_err(|error| {
        // Keep the reason: an introduction that cannot encode is a surface the
        // peer should be told about, not an opaque payload failure.
        Error::Payload(format!("{}: {error}", error.code()))
    })
}

/// Refuse a name the introduction cannot carry.
///
/// A name reaches a module, a fingerprint and a log line, so it is bounded and
/// free of control characters, like a method name in a capability.
fn check_name(kind: &str, name: &str) -> Result<()> {
    // One rule for every name the crate carries: control characters, line and
    // paragraph separators, bidi overrides and invisible formatting are refused,
    // because a name reaches a module, a fingerprint and a log line.
    if !crate::security::valid_text(name, MAX_NAME_BYTES) {
        return Err(Error::InvalidArgument(match kind {
            "peer" => "a peer name must be 1..=1024 bytes without control or reordering characters",
            "provider" => {
                "a provider name must be 1..=1024 bytes without control or reordering characters"
            }
            _ => "a method name must be 1..=1024 bytes without control or reordering characters",
        }));
    }
    Ok(())
}
