use serde::{Deserialize, Deserializer, Serialize, de};

fn de_opt_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum IntOrString {
        Int(usize),
        String(String),
    }

    match Option::<IntOrString>::deserialize(deserializer)? {
        Some(IntOrString::Int(i)) => Ok(Some(i)),
        Some(IntOrString::String(s)) => {
            if s.trim().is_empty() {
                Ok(None)
            } else {
                s.trim()
                    .parse::<usize>()
                    .map(Some)
                    .map_err(de::Error::custom)
            }
        }
        None => Ok(None),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PaginationParams {
    #[serde(default, deserialize_with = "de_opt_usize")]
    pub page: Option<usize>,
    #[serde(default, deserialize_with = "de_opt_usize")]
    pub per_page: Option<usize>,
}

impl PaginationParams {
    pub fn page(&self) -> usize {
        self.page.unwrap_or(1).max(1)
    }

    pub fn per_page(&self, default_per_page: usize) -> usize {
        self.per_page.unwrap_or(default_per_page).clamp(1, 200)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaginatedResponse<T> {
    pub items: Vec<T>,
    pub total_count: usize,
    pub page: usize,
    pub per_page: usize,
    pub total_pages: usize,
}

impl<T: Clone> PaginatedResponse<T> {
    pub fn paginate(all_items: Vec<T>, params: &PaginationParams, default_per_page: usize) -> Self {
        let total_count = all_items.len();
        let page = params.page();
        let per_page = params.per_page(default_per_page);
        let total_pages = if total_count == 0 {
            1
        } else {
            (total_count + per_page - 1) / per_page
        };

        let start = (page - 1) * per_page;
        let items = if start >= total_count {
            Vec::new()
        } else {
            let end = (start + per_page).min(total_count);
            all_items[start..end].to_vec()
        };

        Self {
            items,
            total_count,
            page,
            per_page,
            total_pages,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pagination_logic() {
        let items: Vec<i32> = (1..=25).collect();
        let params = PaginationParams {
            page: Some(2),
            per_page: Some(10),
        };

        let res = PaginatedResponse::paginate(items, &params, 10);
        assert_eq!(res.total_count, 25);
        assert_eq!(res.page, 2);
        assert_eq!(res.per_page, 10);
        assert_eq!(res.total_pages, 3);
        assert_eq!(res.items, vec![11, 12, 13, 14, 15, 16, 17, 18, 19, 20]);
    }
}
