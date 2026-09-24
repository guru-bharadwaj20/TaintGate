//! Positive Datalog prototype: reach(X,Y) :- edge(X,Y).
//! reach(X,Z) :- reach(X,Y), edge(Y,Z). No negation or policy replacement.
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

fn closure(edges: &[(usize, usize)]) -> BTreeSet<(usize, usize)> {
    let mut index: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for &(source, target) in edges {
        index.entry(source).or_default().push(target);
    }
    let mut known: BTreeSet<(usize, usize)> = edges.iter().copied().collect();
    let mut delta = known.clone();
    while !delta.is_empty() {
        let mut next = BTreeSet::new();
        for &(source, middle) in &delta {
            if let Some(targets) = index.get(&middle) {
                for &target in targets {
                    if !known.contains(&(source, target)) {
                        next.insert((source, target));
                    }
                }
            }
        }
        known.extend(next.iter().copied());
        delta = next;
    }
    known
}

fn main() {
    let size: usize = std::env::args().nth(1).unwrap_or("100".into()).parse().expect("size");
    assert!((2..=2000).contains(&size), "size must be 2..2000");
    let edges: Vec<_> = (0..size - 1).map(|i| (i, i + 1)).collect();
    let started = Instant::now();
    let result = closure(&edges);
    println!("{{\"facts\":{},\"elapsed_ns\":{}}}", result.len(), started.elapsed().as_nanos());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cycles_and_duplicates_reach_fixed_point() {
        assert_eq!(closure(&[(0,1),(1,0),(0,1)]),
                   BTreeSet::from([(0,0),(0,1),(1,0),(1,1)]));
    }
    #[test]
    fn disconnected_components_do_not_join() {
        assert_eq!(closure(&[(0,1),(2,3)]).len(), 2);
    }
}
