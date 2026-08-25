use reqwest::Client;
use serde_json::Value;

use super::error::{Result, ShodanError};
use super::types::*;

const BASE_URL: &str = "https://api.shodan.io";

pub struct ShodanClient {
    key: String,
    client: Client,
    base_url: String,
}

impl ShodanClient {
    pub fn new(key: impl Into<String>) -> Self {
        let base_url = std::env::var("SHODAN_API_URL")
            .unwrap_or_else(|_| BASE_URL.to_string());
        ShodanClient {
            key: key.into(),
            client: Client::new(),
            base_url,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_base_url(key: impl Into<String>, base_url: impl Into<String>) -> Self {
        ShodanClient {
            key: key.into(),
            client: Client::new(),
            base_url: base_url.into(),
        }
    }

    async fn get(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut all_params: Vec<(&str, &str)> = vec![("key", &self.key)];
        all_params.extend_from_slice(params);

        let resp = self
            .client
            .get(&url)
            .query(&all_params)
            .send()
            .await?;

        self.parse_response(resp).await
    }

    async fn post_json(&self, path: &str, params: &[(&str, &str)], body: &Value) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut all_params: Vec<(&str, &str)> = vec![("key", &self.key)];
        all_params.extend_from_slice(params);

        let resp = self
            .client
            .post(&url)
            .query(&all_params)
            .json(body)
            .send()
            .await?;

        self.parse_response(resp).await
    }

    async fn delete(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut all_params: Vec<(&str, &str)> = vec![("key", &self.key)];
        all_params.extend_from_slice(params);

        let resp = self
            .client
            .delete(&url)
            .query(&all_params)
            .send()
            .await?;

        self.parse_response(resp).await
    }

    async fn put(&self, path: &str, params: &[(&str, &str)]) -> Result<Value> {
        let url = format!("{}{}", self.base_url, path);
        let mut all_params: Vec<(&str, &str)> = vec![("key", &self.key)];
        all_params.extend_from_slice(params);

        let resp = self
            .client
            .put(&url)
            .query(&all_params)
            .send()
            .await?;

        self.parse_response(resp).await
    }

    async fn parse_response(&self, resp: reqwest::Response) -> Result<Value> {
        let status = resp.status();

        if status == 401 {
            return Err(ShodanError::Api("Invalid API key".to_string()));
        }
        if status == 403 {
            return Err(ShodanError::Api("Access denied (403 Forbidden)".to_string()));
        }
        if status == 502 {
            return Err(ShodanError::Api("Bad Gateway (502)".to_string()));
        }

        let text = resp.text().await?;
        let value: Value = serde_json::from_str(&text)
            .map_err(|_| ShodanError::Api("Unable to parse JSON response".to_string()))?;

        if let Some(err) = value.get("error").and_then(|e| e.as_str()) {
            return Err(ShodanError::Api(err.to_string()));
        }

        Ok(value)
    }

    pub async fn host_info(&self, ip: &str, history: bool, minify: bool) -> Result<HostInfo> {
        let history_s = history.to_string();
        let minify_s = minify.to_string();
        let mut params: Vec<(&str, &str)> = vec![];
        if history {
            params.push(("history", &history_s));
        }
        if minify {
            params.push(("minify", &minify_s));
        }

        let val = self
            .get(&format!("/shodan/host/{}", ip), &params)
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    /// Search with a page number (no limit param sent — they are mutually exclusive).
    pub async fn search_page(
        &self,
        query: &str,
        page: u32,
        facets: Option<&str>,
        fields: Option<&str>,
        minify: bool,
    ) -> Result<SearchResult> {
        let page_s = page.to_string();
        let minify_s = minify.to_string();
        let mut params: Vec<(&str, &str)> =
            vec![("query", query), ("page", &page_s), ("minify", &minify_s)];
        if let Some(f) = facets {
            params.push(("facets", f));
        }
        if let Some(f) = fields {
            params.push(("fields", f));
        }
        let val = self.get("/shodan/host/search", &params).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    /// Search with an explicit limit (no page param sent — they are mutually exclusive).
    pub async fn search_limit(
        &self,
        query: &str,
        limit: u32,
        facets: Option<&str>,
        fields: Option<&str>,
        minify: bool,
    ) -> Result<SearchResult> {
        let limit_s = limit.to_string();
        let minify_s = minify.to_string();
        let mut params: Vec<(&str, &str)> =
            vec![("query", query), ("limit", &limit_s), ("minify", &minify_s)];
        if let Some(f) = facets {
            params.push(("facets", f));
        }
        if let Some(f) = fields {
            params.push(("fields", f));
        }
        let val = self.get("/shodan/host/search", &params).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn count(&self, query: &str, facets: Option<&str>) -> Result<CountResult> {
        let mut params: Vec<(&str, &str)> = vec![("query", query)];
        if let Some(f) = facets {
            params.push(("facets", f));
        }

        let val = self.get("/shodan/host/count", &params).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn api_info(&self) -> Result<ApiInfo> {
        let val = self.get("/api-info", &[]).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn myip(&self) -> Result<String> {
        let val = self.get("/tools/myip", &[]).await?;
        val.as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| ShodanError::Api("Unexpected response format".to_string()))
    }

    pub async fn dns_domain(
        &self,
        domain: &str,
        history: bool,
        record_type: Option<&str>,
        page: u32,
    ) -> Result<DnsDomain> {
        let history_s = history.to_string();
        let page_s = page.to_string();
        let mut params: Vec<(&str, &str)> = vec![("page", &page_s)];
        if history {
            params.push(("history", &history_s));
        }
        if let Some(t) = record_type {
            params.push(("type", t));
        }

        let val = self
            .get(&format!("/dns/domain/{}", domain), &params)
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn scan_submit(&self, ips: &[&str]) -> Result<ScanResult> {
        let networks = ips.join(",");
        let params: Vec<(&str, &str)> = vec![("ips", &networks)];
        let val = self
            .post_json("/shodan/scan", &params, &serde_json::json!({}))
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn scan_status(&self, scan_id: &str) -> Result<ScanStatus> {
        let val = self
            .get(&format!("/shodan/scan/{}", scan_id), &[])
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn alerts(&self) -> Result<Vec<Alert>> {
        let val = self.get("/shodan/alert/info", &[]).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn alert_info(&self, aid: &str) -> Result<Alert> {
        let val = self
            .get(&format!("/shodan/alert/{}/info", aid), &[])
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn create_alert(
        &self,
        name: &str,
        ip: Value,
        expires: i64,
    ) -> Result<Alert> {
        let body = serde_json::json!({
            "name": name,
            "filters": { "ip": ip },
            "expires": expires,
        });
        let val = self.post_json("/shodan/alert", &[], &body).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn delete_alert(&self, aid: &str) -> Result<Value> {
        self.delete(&format!("/shodan/alert/{}", aid), &[]).await
    }

    pub async fn alert_triggers(&self) -> Result<Value> {
        self.get("/shodan/alert/triggers", &[]).await
    }

    pub async fn enable_alert_trigger(&self, aid: &str, trigger: &str) -> Result<Value> {
        self.put(
            &format!("/shodan/alert/{}/trigger/{}", aid, trigger),
            &[],
        )
        .await
    }

    pub async fn disable_alert_trigger(&self, aid: &str, trigger: &str) -> Result<Value> {
        self.delete(
            &format!("/shodan/alert/{}/trigger/{}", aid, trigger),
            &[],
        )
        .await
    }

    pub async fn list_datasets(&self) -> Result<Vec<Dataset>> {
        let val = self.get("/shodan/data", &[]).await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn list_dataset_files(&self, dataset: &str) -> Result<Vec<DataFile>> {
        let val = self
            .get(&format!("/shodan/data/{}", dataset), &[])
            .await?;
        serde_json::from_value(val).map_err(ShodanError::Json)
    }

    pub async fn services(&self) -> Result<Value> {
        self.get("/shodan/services", &[]).await
    }

    pub async fn protocols(&self) -> Result<Value> {
        self.get("/shodan/protocols", &[]).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;

    fn make_client(base_url: &str) -> ShodanClient {
        ShodanClient {
            key: "testkey".to_string(),
            client: Client::new(),
            base_url: base_url.to_string(),
        }
    }

    #[tokio::test]
    async fn test_api_info() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/api-info")
            .match_query(mockito::Matcher::UrlEncoded("key".into(), "testkey".into()))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"scan_credits":0,"usage_limits":{"scan_credits":0,"query_credits":0,"monitored_ips":0},"plan":"dev","unlocked":true,"query_credits":100,"monitored_ips":0,"unlocked_left":0,"telnet":false,"https":true}"#,
            )
            .create_async()
            .await;

        let client = make_client(&server.url());
        let info = client.api_info().await.unwrap();
        assert_eq!(info.plan, "dev");
        assert_eq!(info.query_credits, 100);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_count() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/shodan/host/count")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"total":42}"#)
            .create_async()
            .await;

        let client = make_client(&server.url());
        let result = client.count("apache", None).await.unwrap();
        assert_eq!(result.total, 42);
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn test_401_returns_api_error() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/api-info")
            .match_query(mockito::Matcher::Any)
            .with_status(401)
            .with_body("")
            .create_async()
            .await;

        let client = make_client(&server.url());
        let err = client.api_info().await.unwrap_err();
        assert!(matches!(err, ShodanError::Api(_)));
    }

    #[tokio::test]
    async fn test_error_field_in_response() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/shodan/host/count")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Access restricted"}"#)
            .create_async()
            .await;

        let client = make_client(&server.url());
        let err = client.count("apache", None).await.unwrap_err();
        match err {
            ShodanError::Api(msg) => assert_eq!(msg, "Access restricted"),
            other => panic!("Expected Api error, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_myip() {
        let mut server = Server::new_async().await;
        let _mock = server
            .mock("GET", "/tools/myip")
            .match_query(mockito::Matcher::Any)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#""1.2.3.4""#)
            .create_async()
            .await;

        let client = make_client(&server.url());
        let ip = client.myip().await.unwrap();
        assert_eq!(ip, "1.2.3.4");
    }

    #[tokio::test]
    async fn test_host_info_tags() {
        let mut server = Server::new_async().await;
        let mock = server
            .mock("GET", "/shodan/host/1.2.3.4")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("key".into(), "testkey".into()),
                mockito::Matcher::UrlEncoded("minify".into(), "true".into()),
            ]))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ip_str":"1.2.3.4","tags":["honeypot"]}"#)
            .create_async()
            .await;

        let client = make_client(&server.url());
        let host = client.host_info("1.2.3.4", false, true).await.unwrap();
        assert_eq!(host.tags, Some(vec!["honeypot".to_string()]));
        mock.assert_async().await;
    }
}
