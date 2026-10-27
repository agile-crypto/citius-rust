/// A new identifier: `prefix` followed by a ULID, like `core.NewID` in Go
/// (`key_`, `ver_`, `pol_`, ...). ULIDs sort by creation time and need no
/// coordination, so ids stay unique across contexts and processes.
pub fn new_id(prefix: &str) -> String {
    format!("{prefix}{}", ulid::Ulid::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_carry_the_prefix_and_differ() {
        let a = new_id("key_");
        let b = new_id("key_");
        assert!(a.starts_with("key_"));
        assert_eq!(a.len(), "key_".len() + 26);
        assert_ne!(a, b);
    }
}
