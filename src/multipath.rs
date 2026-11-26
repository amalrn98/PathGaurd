//! Path diversity.
//!
//! Diversity is computed from hop identifiers supplied by the caller (for
//! example autonomous system numbers or router ids from traceroute or a
//! topology database). PathGuard does not discover hops itself. Unknown hops
//! are treated as no evidence of independence.

use std::collections::HashSet;

/// Diversity of two paths: `1 - |A ∩ B| / |A ∪ B|`. Returns 0.0 when either hop
/// list is empty, because independence cannot be shown without data.
pub fn diversity(a: &[String], b: &[String]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let sa: HashSet<&String> = a.iter().collect();
    let sb: HashSet<&String> = b.iter().collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count() as f64;
    1.0 - inter / union
}

/// Smallest pairwise diversity among all paths. `None` for fewer than two paths.
pub fn min_pairwise_diversity(paths: &[&[String]]) -> Option<f64> {
    let mut min: Option<f64> = None;
    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            let d = diversity(paths[i], paths[j]);
            min = Some(min.map_or(d, |m| m.min(d)));
        }
    }
    min
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identical_disjoint_partial_unknown() {
        assert_eq!(diversity(&h(&["a", "b"]), &h(&["a", "b"])), 0.0);
        assert_eq!(diversity(&h(&["a", "b"]), &h(&["c", "d"])), 1.0);
        assert!((diversity(&h(&["a", "b"]), &h(&["b", "c"])) - (1.0 - 1.0 / 3.0)).abs() < 1e-9);
        assert_eq!(diversity(&[], &h(&["a"])), 0.0);
    }

    #[test]
    fn min_pairwise() {
        let (a, b, c) = (h(&["x", "y"]), h(&["x", "z"]), h(&["q", "r"]));
        let m = min_pairwise_diversity(&[&a, &b, &c]).unwrap();
        assert!((m - (1.0 - 1.0 / 3.0)).abs() < 1e-9);
        assert!(min_pairwise_diversity(&[&a]).is_none());
    }
}
