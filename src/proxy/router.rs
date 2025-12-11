use path_tree::PathTree;

use crate::config::Backend;


pub struct Match<'a> {
    pub backend: &'a Backend,
    pub _path: String,
}

#[derive(Debug)]
pub struct Router {
    tree: PathTree<Backend>,
}

const PATHVAR: &str = "subpath";

impl Router {

    pub fn new(backends: &Vec<Backend>) -> Self {
        let mut tree = PathTree::new();

        for b in backends {
            // FIXME: Backend could be Arc, but probably not worth it?
            let backend = b.clone();
            match b.context {
                Some(ref path) => {
                    let path = if path.ends_with("/") {
                        let len = path.len();
                        path.as_str()[..len-1].to_string()
                    } else {
                        path.clone()
                    };
                    let matcher = format!("{path}:{PATHVAR}*");
                    let _id = tree.insert(&matcher, backend);
                }
                None => {
                    let matcher = format!("/:{PATHVAR}*");
                    let _id = tree.insert(&matcher, backend);}
            }
        }

        Router {
            tree
        }
    }

    pub fn lookup(&self, path: &str) -> Option<Match<'_>> {
        let (backend, matched) = self.tree.find(&path)?;
        let rest = matched.params()[0].1.to_string();
        Some(Match {
            backend,
            _path: rest,
        })
    }
}
