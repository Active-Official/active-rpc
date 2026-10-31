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

/// Build the canonical introduction module for a peer.
///
/// `providers` is ordered; the kernel passes its provider table in id order, so
/// the same peer always produces the same bytes.
pub fn build(peer: &str, providers: &[(String, Vec<String>)], budget: &Budget) -> Result<Vec<u8>> {
    let mut module = InfinityModule::new();
    let peer_node = module.push(Inode::Str(peer.to_string()));

    let mut provider_nodes = Vec::with_capacity(providers.len());
    for (provider, methods) in providers {
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

    let budget_fields = vec![
        (
            "max_array_len".to_string(),
            module.push(Inode::Int(budget.max_array_len as i64)),
        ),
        (
            "max_bytes".to_string(),
            module.push(Inode::Int(budget.max_bytes as i64)),
        ),
        (
            "max_calls".to_string(),
            module.push(Inode::Int(budget.max_calls as i64)),
        ),
        (
            "max_depth".to_string(),
            module.push(Inode::Int(budget.max_depth as i64)),
        ),
        (
            "max_nodes".to_string(),
            module.push(Inode::Int(budget.max_nodes as i64)),
        ),
        (
            "max_value_size".to_string(),
            module.push(Inode::Int(budget.max_value_size as i64)),
        ),
        (
            "max_wall_ms".to_string(),
            module.push(Inode::Int(budget.max_wall_ms as i64)),
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
    encode(&module).map_err(|error| Error::Payload(error.code().to_string()))
}
