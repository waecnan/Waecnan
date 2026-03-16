use serde::{Deserialize, Serialize};
use serde_json::Value;

/// JSON-RPC 2.0 request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcRequest {
    pub jsonrpc: String,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    pub id: Value,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcError {
    pub code: i32,
    pub message: String,
}

/// JSON-RPC 2.0 response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
    pub id: Value,
}

impl RpcResponse {
    /// Build a success response.
    pub fn success(id: Value, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Build an error response.
    pub fn error(id: Value, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(RpcError {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

// JSON-RPC 2.0 standard error codes
const METHOD_NOT_FOUND: i32 = -32601;

/// Dispatch a JSON-RPC request to the appropriate handler.
///
/// This is a stub dispatcher — each endpoint returns a placeholder value.
/// In production, handlers would receive references to chain state, mempool, etc.
pub fn dispatch(req: &RpcRequest) -> RpcResponse {
    match req.method.as_str() {
        "getblockcount" => handle_getblockcount(req),
        "getblockhash" => handle_getblockhash(req),
        "getblock" => handle_getblock(req),
        "getrawtransaction" => handle_getrawtransaction(req),
        "sendrawtransaction" => handle_sendrawtransaction(req),
        "getmempoolinfo" => handle_getmempoolinfo(req),
        "getblockchaininfo" => handle_getblockchaininfo(req),
        "getnetworkinfo" => handle_getnetworkinfo(req),
        "getnewaddress" => handle_getnewaddress(req),
        "getbalance" => handle_getbalance(req),
        "stop" => handle_stop(req),
        _ => RpcResponse::error(req.id.clone(), METHOD_NOT_FOUND, "Method not found"),
    }
}

fn handle_getblockcount(req: &RpcRequest) -> RpcResponse {
    // Stub: returns height 0
    RpcResponse::success(req.id.clone(), serde_json::json!(0u64))
}

fn handle_getblockhash(req: &RpcRequest) -> RpcResponse {
    // Stub: returns genesis hash (all zeros)
    let hash = "0".repeat(64);
    RpcResponse::success(req.id.clone(), serde_json::json!(hash))
}

fn handle_getblock(req: &RpcRequest) -> RpcResponse {
    // Stub: returns a minimal block object
    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "hash": "0".repeat(64),
            "height": 0,
            "version": 1,
            "timestamp": 0,
            "difficulty": 1,
            "nonce": 0,
            "tx_count": 0
        }),
    )
}

fn handle_getrawtransaction(req: &RpcRequest) -> RpcResponse {
    // Stub: returns empty tx hex
    RpcResponse::success(req.id.clone(), serde_json::json!(""))
}

fn handle_sendrawtransaction(req: &RpcRequest) -> RpcResponse {
    // Stub: returns a fake txid
    let txid = "0".repeat(64);
    RpcResponse::success(req.id.clone(), serde_json::json!(txid))
}

fn handle_getmempoolinfo(req: &RpcRequest) -> RpcResponse {
    // Stub: empty mempool
    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "size": 0,
            "bytes": 0
        }),
    )
}

fn handle_getblockchaininfo(req: &RpcRequest) -> RpcResponse {
    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "chain": "mainnet",
            "blocks": 0,
            "difficulty": 1
        }),
    )
}

fn handle_getnetworkinfo(req: &RpcRequest) -> RpcResponse {
    RpcResponse::success(
        req.id.clone(),
        serde_json::json!({
            "version": "0.1.0",
            "connections": 0,
            "subversion": "/Waecan:0.1.0/"
        }),
    )
}

fn handle_getnewaddress(req: &RpcRequest) -> RpcResponse {
    // Stub: returns a placeholder bech32m address
    RpcResponse::success(
        req.id.clone(),
        serde_json::json!("wae1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqhqwmpe"),
    )
}

fn handle_getbalance(req: &RpcRequest) -> RpcResponse {
    // Stub: returns zero balance
    RpcResponse::success(req.id.clone(), serde_json::json!(0u64))
}

fn handle_stop(req: &RpcRequest) -> RpcResponse {
    RpcResponse::success(req.id.clone(), serde_json::json!("Waecan server stopping"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(method: &str) -> RpcRequest {
        RpcRequest {
            jsonrpc: "2.0".to_string(),
            method: method.to_string(),
            params: Value::Null,
            id: Value::Number(serde_json::Number::from(1)),
        }
    }

    #[test]
    fn test_unknown_method_returns_error() {
        let req = make_request("nonexistent");
        let resp = dispatch(&req);
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, -32601);
        assert!(resp.result.is_none());
    }

    #[test]
    fn test_getblockcount_returns_u64() {
        let req = make_request("getblockcount");
        let resp = dispatch(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.is_u64());
    }

    #[test]
    fn test_getmempoolinfo_returns_object() {
        let req = make_request("getmempoolinfo");
        let resp = dispatch(&req);
        assert!(resp.error.is_none());
        let result = resp.result.unwrap();
        assert!(result.is_object());
        let obj = result.as_object().unwrap();
        assert!(obj.contains_key("size"));
        assert!(obj.contains_key("bytes"));
    }

    #[test]
    fn test_rpc_request_deserializes() {
        let json = r#"{"jsonrpc":"2.0","method":"getblockcount","params":null,"id":42}"#;
        let req: RpcRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.method, "getblockcount");
        assert_eq!(req.id, Value::Number(serde_json::Number::from(42)));
    }

    #[test]
    fn test_rpc_response_serializes_to_valid_envelope() {
        let resp = RpcResponse::success(
            Value::Number(serde_json::Number::from(1)),
            serde_json::json!(100),
        );
        let json = serde_json::to_string(&resp).unwrap();
        let parsed: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["jsonrpc"], "2.0");
        assert_eq!(parsed["id"], 1);
        assert_eq!(parsed["result"], 100);
        assert!(parsed.get("error").is_none());
    }
}
