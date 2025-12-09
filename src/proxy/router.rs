use path_tree::PathTree;

use crate::config::Backend;


pub struct Match<'a> {
    pub backend: &'a Backend,
    pub path: String,
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
            path: rest,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use http::Uri;
    use test_log::test;
    use crate::config::Backend;

    #[test]
    fn test_router() -> Result<()> {
        let backends = vec![
            Backend {
                context: None,
                url: Uri::from_static("http://localhost:1010")
            },
            Backend {
                context: Some("/service".to_string()),
                url: Uri::from_static("http://localhost:2020")
            },
            Backend {
                context: Some("/service/subservice/".to_string()),
                url: Uri::from_static("http://localhost:3030")
            },
            Backend {
                context: Some("/other_service/".to_string()),
                url: Uri::from_static("http://localhost:4040")
            },
        ];

        let router = Router::new(&backends);

        let matched = router.lookup("/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/base/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:1010"), matched.backend.url);
        assert_eq!("base/path", matched.path);

        let matched = router.lookup("/service").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/service/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("/", matched.path);

        let matched = router.lookup("/service/some/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:2020"), matched.backend.url);
        assert_eq!("/some/path", matched.path);

        let matched = router.lookup("/service/subservice").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("", matched.path);

        let matched = router.lookup("/service/subservice/").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("/", matched.path);

        let matched = router.lookup("/service/subservice/ss/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:3030"), matched.backend.url);
        assert_eq!("/ss/path", matched.path);

        let matched = router.lookup("/other_service/some/path").unwrap();
        assert_eq!(Uri::from_static("http://localhost:4040"), matched.backend.url);
        assert_eq!("/some/path", matched.path);

        Ok(())
    }

}
