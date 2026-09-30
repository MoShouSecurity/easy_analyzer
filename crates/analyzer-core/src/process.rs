//! Structured process relationships, namespaced by evidence source.
use crate::{Record, RecordData};
use std::collections::{BTreeMap, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct ProcessNode {
    pub record_id: String,
    pub pid: u32,
    pub parent_id: Option<String>,
    pub children: Vec<String>,
    pub orphan: bool,
    pub cyclic: bool,
}

#[derive(Debug, Clone)]
pub struct ProcessTree {
    pub source_id: String,
    pub roots: Vec<String>,
    pub cycle_roots: Vec<String>,
    pub nodes: Vec<ProcessNode>,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessForest {
    pub trees: Vec<ProcessTree>,
}

pub fn process_forest(records: &[Record]) -> ProcessForest {
    let mut groups: BTreeMap<&str, Vec<_>> = BTreeMap::new();
    for record in records {
        if let RecordData::Process(process) = &record.data {
            groups
                .entry(&record.source_id)
                .or_default()
                .push((record, process));
        }
    }
    let trees = groups
        .into_iter()
        .map(|(source_id, mut records)| {
            records.sort_by(|(a, pa), (b, pb)| (pa.pid, &a.id).cmp(&(pb.pid, &b.id)));
            let mut pids = HashMap::new();
            for (index, (_, process)) in records.iter().enumerate() {
                pids.entry(process.pid).or_insert(index);
            }
            let parents: Vec<_> = records
                .iter()
                .map(|(_, process)| process.parent_pid.and_then(|pid| pids.get(&pid).copied()))
                .collect();
            let mut nodes: Vec<_> = records
                .iter()
                .enumerate()
                .map(|(i, (record, process))| ProcessNode {
                    record_id: record.id.clone(),
                    pid: process.pid,
                    parent_id: parents[i].map(|p| records[p].0.id.clone()),
                    children: vec![],
                    orphan: process.parent_pid.is_some() && parents[i].is_none(),
                    cyclic: false,
                })
                .collect();
            let mut roots = vec![];
            for (i, parent) in parents.iter().enumerate() {
                if let Some(parent) = parent {
                    let id = nodes[i].record_id.clone();
                    nodes[*parent].children.push(id);
                } else {
                    roots.push(nodes[i].record_id.clone());
                }
            }
            // Iterative parent walks avoid recursion and quadratic scans on deep snapshots.
            let mut finished = HashSet::new();
            let mut cycle_roots = vec![];
            for start in 0..nodes.len() {
                if finished.contains(&start) {
                    continue;
                }
                let mut path: Vec<usize> = vec![];
                let mut positions: HashMap<usize, usize> = HashMap::new();
                let mut cursor = Some(start);
                while let Some(i) = cursor {
                    if finished.contains(&i) {
                        break;
                    }
                    if let Some(&position) = positions.get(&i) {
                        let cycle = &path[position..];
                        let root = *cycle.iter().min().expect("nonempty cycle");
                        cycle_roots.push(nodes[root].record_id.clone());
                        for &member in cycle {
                            nodes[member].cyclic = true;
                        }
                        break;
                    }
                    positions.insert(i, path.len());
                    path.push(i);
                    cursor = parents[i];
                }
                finished.extend(path);
            }
            ProcessTree {
                source_id: source_id.into(),
                roots,
                cycle_roots,
                nodes,
            }
        })
        .collect();
    ProcessForest { trees }
}
