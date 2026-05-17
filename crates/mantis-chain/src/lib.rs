//! Capability-graph chain discovery (PRD §5.7.7, §10.4).
//!
//! PRD §5.7.7: "The system shall support multi-step chain exploits
//! expressed as path queries over the capability graph."
//!
//! PRD §10.4 specifies the algorithm:
//! - Path-finding constrained by:
//!   - capability composition rules (a primitive's output must
//!     satisfy the next primitive's preconditions)
//!   - total request cost budget
//!   - chain length limit (configurable, default 5)
//! - Returned paths ranked by composite impact score, declining as
//!   chain length grows.
//!
//! This crate implements that algorithm as a depth-first search
//! over a typed capability graph. The daemon populates the graph
//! from observed claims (each claim grants a capability) and
//! queries it whenever a primitive's output capability matches
//! another primitive's precondition.

use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ChainError {
    #[error("primitive {0} referenced but not in catalog")]
    UnknownPrimitive(String),
}

/// A typed capability. Concrete strings like "read.user_email",
/// "exec.shell", "tenant.admin" — the daemon's playbook system
/// defines the vocabulary; this crate only cares about equality.
pub type Capability = String;

/// A primitive declares the capabilities it requires (preconditions)
/// and the capabilities it produces. The synthesizer-side
/// `mantis-primitive` crate's primitives map onto this descriptor
/// when the chain planner indexes them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrimitiveDescriptor {
    pub id: String,
    pub preconditions: Vec<Capability>,
    pub produces: Vec<Capability>,
    /// Estimated request cost (1 = one HTTP request, 10 = a full
    /// brute force). Used by the chain ranker.
    pub request_cost: u32,
    /// Heuristic impact score for the capability the primitive
    /// produces. Higher is worse (more impactful) on a 0..100 scale.
    pub impact: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CapabilityGraph {
    primitives: Vec<PrimitiveDescriptor>,
    /// Initial capabilities the engagement starts with (typically
    /// an empty set; recon-driven capabilities like
    /// "host.discovered" get added before chain discovery).
    initial: HashSet<Capability>,
}

impl CapabilityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_initial(mut self, caps: impl IntoIterator<Item = Capability>) -> Self {
        self.initial = caps.into_iter().collect();
        self
    }

    pub fn add_primitive(&mut self, descriptor: PrimitiveDescriptor) {
        self.primitives.push(descriptor);
    }

    pub fn primitive_count(&self) -> usize {
        self.primitives.len()
    }

    /// Discover chains whose terminal primitive produces
    /// `goal_capability`. Returns up to `max_results` chains sorted
    /// by impact score, declining (highest impact first).
    pub fn discover_chains(&self, goal_capability: &str, opts: ChainSearchOptions) -> Vec<Chain> {
        let mut by_id: HashMap<&str, &PrimitiveDescriptor> = HashMap::new();
        for p in &self.primitives {
            by_id.insert(&p.id, p);
        }
        let mut chains = Vec::<Chain>::new();
        let mut path: Vec<&PrimitiveDescriptor> = Vec::new();
        let mut owned: HashSet<Capability> = self.initial.clone();
        let mut cost = 0u32;
        self.dfs(
            goal_capability,
            &opts,
            &mut owned,
            &mut path,
            &mut cost,
            &mut chains,
        );
        chains.sort_by_key(|c| std::cmp::Reverse(c.impact_score));
        chains.truncate(opts.max_results);
        chains
    }

    fn dfs<'g>(
        &'g self,
        goal: &str,
        opts: &ChainSearchOptions,
        owned: &mut HashSet<Capability>,
        path: &mut Vec<&'g PrimitiveDescriptor>,
        cost: &mut u32,
        out: &mut Vec<Chain>,
    ) {
        if path.len() >= opts.max_length {
            return;
        }
        if *cost >= opts.max_request_cost {
            return;
        }
        if out.len() >= opts.max_results * 4 {
            // Trim early; final sort+truncate happens at the
            // caller. 4× cap gives the ranker enough headroom to
            // pick the best regardless of DFS visit order.
            return;
        }

        for prim in &self.primitives {
            if path.iter().any(|p| p.id == prim.id) {
                continue;
            }
            if !prim.preconditions.iter().all(|c| owned.contains(c)) {
                continue;
            }
            let mut added: Vec<Capability> = Vec::new();
            for produced in &prim.produces {
                if owned.insert(produced.clone()) {
                    added.push(produced.clone());
                }
            }
            path.push(prim);
            *cost += prim.request_cost;

            if *cost <= opts.max_request_cost {
                if prim.produces.iter().any(|p| p == goal) {
                    out.push(Chain::from_path(path));
                } else {
                    self.dfs(goal, opts, owned, path, cost, out);
                }
            }

            path.pop();
            *cost -= prim.request_cost;
            for cap in added {
                owned.remove(&cap);
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ChainSearchOptions {
    pub max_length: usize,
    pub max_request_cost: u32,
    pub max_results: usize,
}

impl Default for ChainSearchOptions {
    fn default() -> Self {
        Self {
            max_length: 5,
            max_request_cost: 50,
            max_results: 10,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub steps: Vec<String>,
    pub total_request_cost: u32,
    /// Composite impact score. Sum of per-step impacts discounted
    /// by chain length: each additional step multiplies the
    /// previous score by 0.9 — implemented integer-safely as
    /// `sum * (10 - len).max(1) / 10`.
    pub impact_score: u32,
}

impl Chain {
    fn from_path(path: &[&PrimitiveDescriptor]) -> Self {
        let steps: Vec<String> = path.iter().map(|p| p.id.clone()).collect();
        let total_request_cost: u32 = path.iter().map(|p| p.request_cost).sum();
        // Use the MAX per-step impact rather than sum, then apply
        // a strong length penalty. Sum-of-impacts rewards longer
        // chains (more moving parts), which is the opposite of
        // PRD §10.4's "declining as chain length grows" rule.
        let max_step_impact: u32 = path.iter().map(|p| p.impact).max().unwrap_or(0);
        let len = steps.len() as u32;
        // Each extra step halves the score (integer division). A
        // single-step chain keeps full impact; 2 steps → 50%, 3 →
        // 25%, etc. Aligns with the PRD's "declining" language.
        let divisor = 1u32 << (len.saturating_sub(1)).min(8);
        let impact_score = max_step_impact / divisor;
        Self {
            steps,
            total_request_cost,
            impact_score,
        }
    }

    pub fn length(&self) -> usize {
        self.steps.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prim(
        id: &str,
        preconds: &[&str],
        produces: &[&str],
        cost: u32,
        impact: u32,
    ) -> PrimitiveDescriptor {
        PrimitiveDescriptor {
            id: id.into(),
            preconditions: preconds.iter().map(|s| s.to_string()).collect(),
            produces: produces.iter().map(|s| s.to_string()).collect(),
            request_cost: cost,
            impact,
        }
    }

    #[test]
    fn empty_graph_returns_no_chains() {
        let g = CapabilityGraph::new();
        let chains = g.discover_chains("admin", ChainSearchOptions::default());
        assert!(chains.is_empty());
    }

    #[test]
    fn single_primitive_satisfying_initial_finds_one_step_chain() {
        let mut g = CapabilityGraph::new().with_initial(vec!["host.discovered".into()]);
        g.add_primitive(prim("idor", &["host.discovered"], &["read.user"], 1, 50));
        let chains = g.discover_chains("read.user", ChainSearchOptions::default());
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].steps, vec!["idor"]);
    }

    #[test]
    fn two_step_chain_composes_capabilities() {
        let mut g = CapabilityGraph::new().with_initial(vec!["host.discovered".into()]);
        g.add_primitive(prim(
            "recon",
            &["host.discovered"],
            &["endpoint.found"],
            2,
            10,
        ));
        g.add_primitive(prim("sqli", &["endpoint.found"], &["read.db"], 5, 70));
        let chains = g.discover_chains("read.db", ChainSearchOptions::default());
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].steps, vec!["recon", "sqli"]);
        assert_eq!(chains[0].total_request_cost, 7);
    }

    #[test]
    fn impact_score_discounts_longer_chains() {
        let mut g = CapabilityGraph::new().with_initial(vec!["a".into()]);
        g.add_primitive(prim("short", &["a"], &["goal"], 1, 100));
        g.add_primitive(prim("mid1", &["a"], &["b"], 1, 50));
        g.add_primitive(prim("mid2", &["b"], &["c"], 1, 50));
        g.add_primitive(prim("mid3", &["c"], &["goal"], 1, 50));
        let chains = g.discover_chains("goal", ChainSearchOptions::default());
        // The single-step chain should rank higher than the
        // multi-step path with the same total raw impact.
        assert_eq!(chains[0].steps, vec!["short"]);
    }

    #[test]
    fn respects_max_length() {
        let mut g = CapabilityGraph::new().with_initial(vec!["a".into()]);
        g.add_primitive(prim("p1", &["a"], &["b"], 1, 10));
        g.add_primitive(prim("p2", &["b"], &["c"], 1, 10));
        g.add_primitive(prim("p3", &["c"], &["goal"], 1, 10));
        let opts = ChainSearchOptions {
            max_length: 2,
            ..Default::default()
        };
        let chains = g.discover_chains("goal", opts);
        assert!(chains.is_empty());
    }

    #[test]
    fn respects_max_request_cost() {
        let mut g = CapabilityGraph::new().with_initial(vec!["a".into()]);
        g.add_primitive(prim("expensive", &["a"], &["goal"], 100, 90));
        let opts = ChainSearchOptions {
            max_request_cost: 10,
            ..Default::default()
        };
        let chains = g.discover_chains("goal", opts);
        assert!(chains.is_empty());
    }

    #[test]
    fn primitive_count_reports_catalog_size() {
        let mut g = CapabilityGraph::new();
        g.add_primitive(prim("a", &[], &["x"], 1, 1));
        g.add_primitive(prim("b", &["x"], &["y"], 1, 1));
        assert_eq!(g.primitive_count(), 2);
    }

    #[test]
    fn does_not_reuse_same_primitive_within_one_chain() {
        let mut g = CapabilityGraph::new().with_initial(vec!["a".into()]);
        // p1 produces "a" too — without dedup we'd loop.
        g.add_primitive(prim("p1", &["a"], &["a", "b"], 1, 10));
        g.add_primitive(prim("p2", &["b"], &["goal"], 1, 50));
        let chains = g.discover_chains("goal", ChainSearchOptions::default());
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].steps, vec!["p1", "p2"]);
    }

    #[test]
    fn multiple_chains_returned_sorted_by_impact() {
        let mut g = CapabilityGraph::new().with_initial(vec!["a".into()]);
        g.add_primitive(prim("low", &["a"], &["goal"], 1, 20));
        g.add_primitive(prim("via1", &["a"], &["b"], 1, 5));
        g.add_primitive(prim("via2", &["b"], &["goal"], 1, 80));
        let chains = g.discover_chains("goal", ChainSearchOptions::default());
        // Some graphs surface multiple traversals to the goal; the
        // ranker should put the highest-impact chain first.
        // via1→via2: max-step impact 80, len 2, score=80/2=40.
        // low alone:  max-step impact 20, len 1, score=20.
        assert!(chains.len() >= 2);
        assert_eq!(chains[0].steps[chains[0].steps.len() - 1], "via2");
    }
}
