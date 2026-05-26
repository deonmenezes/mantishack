//! OpenAPI 3.x / Swagger 2.0 schema parser.
//!
//! Reads the JSON or YAML wire format (auto-detected) and emits a
//! flat list of [`ApiEndpoint`]s the rest of the pipeline can act on.
//! We deliberately do NOT validate the spec — pentest targets often
//! ship slightly-broken specs and we want every reachable endpoint,
//! not a strict conformance check.

use crate::ApiError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterIn {
    Query,
    Header,
    Path,
    Cookie,
    Body,
    FormData,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParameterType {
    String,
    Integer,
    Number,
    Boolean,
    Array,
    Object,
    Uuid,
    DateTime,
    Email,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiParameter {
    pub name: String,
    #[serde(rename = "in")]
    pub location: ParameterIn,
    pub required: bool,
    #[serde(rename = "type")]
    pub typ: ParameterType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiEndpoint {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub parameters: Vec<ApiParameter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Auth scheme names referenced by the security clause for this
    /// operation (e.g. `["bearerAuth", "apiKey"]`). Empty if the
    /// operation explicitly opts out of security.
    #[serde(default)]
    pub security: Vec<String>,
}

/// Parse JSON or YAML schema text. Detects format by the first
/// non-whitespace character (`{` or `[` → JSON; else YAML).
pub fn parse(text: &str) -> Result<Vec<ApiEndpoint>, ApiError> {
    let doc = parse_to_json(text)?;
    if doc.get("openapi").is_some() {
        parse_openapi3(&doc)
    } else if doc.get("swagger").is_some() {
        parse_swagger2(&doc)
    } else {
        Err(ApiError::UnsupportedSchema(
            "missing both `openapi` and `swagger` top-level fields".into(),
        ))
    }
}

fn parse_to_json(text: &str) -> Result<serde_json::Value, ApiError> {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        serde_json::from_str(text).map_err(|e| ApiError::Parse(format!("json: {e}")))
    } else {
        serde_yaml_ng::from_str(text).map_err(|e| ApiError::Parse(format!("yaml: {e}")))
    }
}

fn parse_openapi3(doc: &serde_json::Value) -> Result<Vec<ApiEndpoint>, ApiError> {
    let paths = match doc.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (path, item) in paths {
        let item_obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        // Path-level parameters apply to all operations.
        let path_params = item_obj
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(extract_openapi3_parameter)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for method in HTTP_METHODS {
            let op = match item_obj.get(*method).and_then(|v| v.as_object()) {
                Some(o) => o,
                None => continue,
            };
            let mut params = path_params.clone();
            if let Some(arr) = op.get("parameters").and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(parsed) = extract_openapi3_parameter(p) {
                        params.push(parsed);
                    }
                }
            }
            // Body parameter — OpenAPI 3 has requestBody.content.<media>.schema
            if let Some(body) = op.get("requestBody").and_then(|v| v.as_object()) {
                let required = body
                    .get("required")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                if let Some(content) = body.get("content").and_then(|v| v.as_object()) {
                    for media in content.keys() {
                        params.push(ApiParameter {
                            name: format!("body[{media}]"),
                            location: ParameterIn::Body,
                            required,
                            typ: ParameterType::Object,
                            example: None,
                        });
                    }
                }
            }
            let security = op
                .get("security")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .flat_map(|s| {
                            s.as_object()
                                .map(|m| m.keys().cloned().collect::<Vec<_>>())
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(ApiEndpoint {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                parameters: params,
                operation_id: op
                    .get("operationId")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                summary: op.get("summary").and_then(|v| v.as_str()).map(String::from),
                security,
            });
        }
    }
    Ok(out)
}

fn parse_swagger2(doc: &serde_json::Value) -> Result<Vec<ApiEndpoint>, ApiError> {
    let paths = match doc.get("paths").and_then(|v| v.as_object()) {
        Some(p) => p,
        None => return Ok(Vec::new()),
    };
    let mut out = Vec::new();
    for (path, item) in paths {
        let item_obj = match item.as_object() {
            Some(o) => o,
            None => continue,
        };
        let path_params = item_obj
            .get("parameters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(extract_swagger2_parameter)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        for method in HTTP_METHODS {
            let op = match item_obj.get(*method).and_then(|v| v.as_object()) {
                Some(o) => o,
                None => continue,
            };
            let mut params = path_params.clone();
            if let Some(arr) = op.get("parameters").and_then(|v| v.as_array()) {
                for p in arr {
                    if let Some(parsed) = extract_swagger2_parameter(p) {
                        params.push(parsed);
                    }
                }
            }
            let security = op
                .get("security")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .flat_map(|s| {
                            s.as_object()
                                .map(|m| m.keys().cloned().collect::<Vec<_>>())
                                .unwrap_or_default()
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.push(ApiEndpoint {
                method: method.to_ascii_uppercase(),
                path: path.clone(),
                parameters: params,
                operation_id: op
                    .get("operationId")
                    .and_then(|v| v.as_str())
                    .map(String::from),
                summary: op.get("summary").and_then(|v| v.as_str()).map(String::from),
                security,
            });
        }
    }
    Ok(out)
}

fn extract_openapi3_parameter(p: &serde_json::Value) -> Option<ApiParameter> {
    let obj = p.as_object()?;
    let name = obj.get("name").and_then(|v| v.as_str())?.to_string();
    let location = parse_location(obj.get("in").and_then(|v| v.as_str())?)?;
    let required = obj
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(location == ParameterIn::Path);
    let schema = obj.get("schema").and_then(|v| v.as_object());
    let typ = schema
        .and_then(|s| {
            let t = s.get("type").and_then(|v| v.as_str())?;
            let fmt = s.get("format").and_then(|v| v.as_str());
            Some(parse_type(t, fmt))
        })
        .unwrap_or(ParameterType::Unknown);
    let example = obj
        .get("example")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            schema
                .and_then(|s| s.get("example"))
                .and_then(|v| v.as_str())
                .map(String::from)
        });
    Some(ApiParameter {
        name,
        location,
        required,
        typ,
        example,
    })
}

fn extract_swagger2_parameter(p: &serde_json::Value) -> Option<ApiParameter> {
    let obj = p.as_object()?;
    let name = obj.get("name").and_then(|v| v.as_str())?.to_string();
    let location_str = obj.get("in").and_then(|v| v.as_str())?;
    let location = parse_location(location_str)?;
    let required = obj
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(location == ParameterIn::Path);
    let t = obj.get("type").and_then(|v| v.as_str());
    let fmt = obj.get("format").and_then(|v| v.as_str());
    let typ = match t {
        Some(name) => parse_type(name, fmt),
        None => ParameterType::Unknown,
    };
    let example = obj
        .get("example")
        .and_then(|v| v.as_str())
        .map(String::from);
    Some(ApiParameter {
        name,
        location,
        required,
        typ,
        example,
    })
}

fn parse_location(s: &str) -> Option<ParameterIn> {
    Some(match s.to_ascii_lowercase().as_str() {
        "query" => ParameterIn::Query,
        "header" => ParameterIn::Header,
        "path" => ParameterIn::Path,
        "cookie" => ParameterIn::Cookie,
        "body" => ParameterIn::Body,
        "formdata" | "form" => ParameterIn::FormData,
        _ => return None,
    })
}

fn parse_type(t: &str, fmt: Option<&str>) -> ParameterType {
    if let Some(fmt) = fmt {
        match fmt {
            "uuid" => return ParameterType::Uuid,
            "date-time" | "datetime" | "date" => return ParameterType::DateTime,
            "email" => return ParameterType::Email,
            _ => {}
        }
    }
    match t {
        "string" => ParameterType::String,
        "integer" => ParameterType::Integer,
        "number" => ParameterType::Number,
        "boolean" => ParameterType::Boolean,
        "array" => ParameterType::Array,
        "object" => ParameterType::Object,
        _ => ParameterType::Unknown,
    }
}

const HTTP_METHODS: &[&str] = &[
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_OPENAPI3: &str = r#"{
        "openapi": "3.0.0",
        "info": {"title": "test", "version": "1.0"},
        "paths": {
            "/users/{id}": {
                "parameters": [
                    {"name":"id","in":"path","required":true,"schema":{"type":"string","format":"uuid"}}
                ],
                "get": {
                    "operationId":"getUser",
                    "summary":"fetch one user",
                    "parameters":[
                        {"name":"verbose","in":"query","schema":{"type":"boolean"}}
                    ],
                    "security":[{"bearerAuth":[]}]
                },
                "patch": {
                    "operationId":"patchUser",
                    "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object"}}}}
                }
            },
            "/health": {"get":{"operationId":"health"}}
        }
    }"#;

    const SAMPLE_SWAGGER2: &str = r#"{
        "swagger":"2.0",
        "info":{"title":"old","version":"1.0"},
        "paths":{
            "/items":{
                "get":{
                    "parameters":[
                        {"name":"limit","in":"query","type":"integer"},
                        {"name":"sort","in":"query","type":"string"}
                    ]
                },
                "post":{
                    "parameters":[
                        {"name":"body","in":"body","required":true}
                    ],
                    "security":[{"apiKey":[]}]
                }
            }
        }
    }"#;

    #[test]
    fn parses_openapi3_paths_and_methods() {
        let endpoints = parse(SAMPLE_OPENAPI3).unwrap();
        let methods: std::collections::BTreeSet<(String, String)> = endpoints
            .iter()
            .map(|e| (e.method.clone(), e.path.clone()))
            .collect();
        assert!(methods.contains(&("GET".into(), "/users/{id}".into())));
        assert!(methods.contains(&("PATCH".into(), "/users/{id}".into())));
        assert!(methods.contains(&("GET".into(), "/health".into())));
    }

    #[test]
    fn openapi3_inherits_path_level_parameters() {
        let endpoints = parse(SAMPLE_OPENAPI3).unwrap();
        let get_user = endpoints
            .iter()
            .find(|e| e.method == "GET" && e.path == "/users/{id}")
            .unwrap();
        // path-level id + operation-level verbose
        assert!(get_user.parameters.iter().any(|p| p.name == "id"));
        assert!(get_user.parameters.iter().any(|p| p.name == "verbose"));
    }

    #[test]
    fn openapi3_path_param_id_is_typed_as_uuid_and_required() {
        let endpoints = parse(SAMPLE_OPENAPI3).unwrap();
        let id_param = endpoints
            .iter()
            .flat_map(|e| e.parameters.iter())
            .find(|p| p.name == "id")
            .unwrap();
        assert_eq!(id_param.typ, ParameterType::Uuid);
        assert_eq!(id_param.location, ParameterIn::Path);
        assert!(id_param.required);
    }

    #[test]
    fn openapi3_request_body_emits_body_parameter() {
        let endpoints = parse(SAMPLE_OPENAPI3).unwrap();
        let patch = endpoints
            .iter()
            .find(|e| e.method == "PATCH" && e.path == "/users/{id}")
            .unwrap();
        assert!(patch
            .parameters
            .iter()
            .any(|p| p.location == ParameterIn::Body && p.required));
    }

    #[test]
    fn openapi3_security_clause_captured() {
        let endpoints = parse(SAMPLE_OPENAPI3).unwrap();
        let get_user = endpoints
            .iter()
            .find(|e| e.method == "GET" && e.path == "/users/{id}")
            .unwrap();
        assert!(get_user.security.contains(&"bearerAuth".to_string()));
    }

    #[test]
    fn parses_swagger2_basic() {
        let endpoints = parse(SAMPLE_SWAGGER2).unwrap();
        assert_eq!(endpoints.len(), 2);
        let post = endpoints
            .iter()
            .find(|e| e.method == "POST" && e.path == "/items")
            .unwrap();
        assert!(post
            .parameters
            .iter()
            .any(|p| p.location == ParameterIn::Body && p.required));
        assert!(post.security.contains(&"apiKey".to_string()));
    }

    #[test]
    fn swagger2_type_int_is_integer() {
        let endpoints = parse(SAMPLE_SWAGGER2).unwrap();
        let get = endpoints
            .iter()
            .find(|e| e.method == "GET" && e.path == "/items")
            .unwrap();
        let limit = get.parameters.iter().find(|p| p.name == "limit").unwrap();
        assert_eq!(limit.typ, ParameterType::Integer);
    }

    #[test]
    fn yaml_input_is_auto_detected() {
        let yaml = r#"
openapi: 3.0.0
info: {title: yaml-test, version: '1.0'}
paths:
  /ping:
    get:
      operationId: ping
"#;
        let endpoints = parse(yaml).unwrap();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/ping");
        assert_eq!(endpoints[0].method, "GET");
    }

    #[test]
    fn missing_paths_returns_empty_vec() {
        let doc = r#"{"openapi":"3.0.0","info":{"title":"x","version":"1"}}"#;
        let endpoints = parse(doc).unwrap();
        assert!(endpoints.is_empty());
    }

    #[test]
    fn unknown_schema_returns_unsupported_error() {
        let doc = r#"{"hello":"world"}"#;
        match parse(doc) {
            Err(ApiError::UnsupportedSchema(_)) => {}
            other => panic!("expected UnsupportedSchema, got {other:?}"),
        }
    }

    #[test]
    fn bad_json_returns_parse_error() {
        let r = parse("{not-json");
        assert!(matches!(r, Err(ApiError::Parse(_))));
    }

    #[test]
    fn api_endpoint_round_trips_through_serde() {
        let e = ApiEndpoint {
            method: "GET".into(),
            path: "/users/{id}".into(),
            parameters: vec![ApiParameter {
                name: "id".into(),
                location: ParameterIn::Path,
                required: true,
                typ: ParameterType::Uuid,
                example: None,
            }],
            operation_id: Some("getUser".into()),
            summary: None,
            security: vec!["bearerAuth".into()],
        };
        let j = serde_json::to_string(&e).unwrap();
        let back: ApiEndpoint = serde_json::from_str(&j).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn parse_location_handles_all_known_values() {
        for (s, expected) in [
            ("query", ParameterIn::Query),
            ("header", ParameterIn::Header),
            ("path", ParameterIn::Path),
            ("cookie", ParameterIn::Cookie),
            ("body", ParameterIn::Body),
            ("formData", ParameterIn::FormData),
        ] {
            assert_eq!(parse_location(s), Some(expected));
        }
        assert_eq!(parse_location("nonsense"), None);
    }

    #[test]
    fn parse_type_format_overrides_base_type() {
        assert_eq!(parse_type("string", Some("uuid")), ParameterType::Uuid);
        assert_eq!(
            parse_type("string", Some("date-time")),
            ParameterType::DateTime
        );
        assert_eq!(parse_type("string", Some("email")), ParameterType::Email);
        assert_eq!(parse_type("string", None), ParameterType::String);
        assert_eq!(parse_type("integer", None), ParameterType::Integer);
        assert_eq!(parse_type("boolean", None), ParameterType::Boolean);
        assert_eq!(parse_type("wat", None), ParameterType::Unknown);
    }
}
