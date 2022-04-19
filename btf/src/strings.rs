pub struct StringsTable(pub Vec<u8>);

impl StringsTable {
    pub fn optional_name(&self, offset: usize) -> Option<String> {
        if offset == 0 {
            None
        } else {
            Some(self.name(offset))
        }
    }

    pub fn name(&self, offset: usize) -> String {
        assert!(offset != 0);
        assert!((offset as usize) < self.0.len());

        let name: Vec<_> = self.0[offset..]
            .iter()
            .copied()
            .take_while(|&b| b != 0_u8)
            .collect();

        String::from_utf8(name).unwrap()
    }
}
