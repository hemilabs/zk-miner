use super::*;
use proptest::prelude::*;

const SR: MethodSet = MethodSet::StateRead;
const ST: MethodSet = MethodSet::StateTrace;

const LATEST: u64 = 1000;
const SAFE: u64 = 990;
const FINALIZED: u64 = 980;

fn resolve(t: BlockTag) -> u64 {
    match t {
        BlockTag::Latest => LATEST,
        BlockTag::Safe => SAFE,
        BlockTag::Finalized => FINALIZED,
    }
}

fn h(b: u8) -> String {
    format!("0x{}", format!("{b:02x}").repeat(32))
}

fn a(b: u8) -> String {
    format!("0x{}", format!("{b:02x}").repeat(20))
}

fn call_json(method: &str, params: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#)
}

fn p(method: &str, params: &str) -> Result<ParsedRequest, Denied> {
    parse_request(call_json(method, params).as_bytes(), SR)
}

#[track_caller]
fn ok(method: &str, params: &str) -> ParsedRequest {
    p(method, params).unwrap_or_else(|e| panic!("{method} {params}: {e:?}"))
}

#[track_caller]
fn err(method: &str, params: &str) -> Denied {
    match p(method, params) {
        Ok(r) => panic!("{method} {params} parsed: {r:?}"),
        Err(e) => e,
    }
}

/// `s` with every `§` turned into a backslash: how these tests spell JSON `\u` escapes.
fn j(s: &str) -> String {
    s.replace('§', "\\")
}

fn raw(s: &str) -> Result<ParsedRequest, Denied> {
    parse_request(s.as_bytes(), SR)
}

fn out(r: &ParsedRequest, first_id: u64) -> String {
    String::from_utf8(r.outgoing(&resolve, first_id)).unwrap()
}

/// The params array the broker sends for a single call.
#[track_caller]
fn sent(method: &str, params: &str) -> String {
    let o = out(&ok(method, params), 7);
    let prefix = format!(r#"{{"jsonrpc":"2.0","id":7,"method":"{method}","params":"#);
    o.strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or_else(|| panic!("{o}"))
        .to_string()
}

const GAS_CAP_HEX: &str = "0x1c9c380";

// ------------------------------------------------------------------------------------------------
// Requests: every method, arity, encodings.

#[test]
fn every_method_parses_and_is_re_encoded() {
    let (h1, h2, a1) = (h(0x11), h(0x22), a(0xaa));
    let h1u = h1.to_uppercase().replacen("0X", "0x", 1);
    let zero_slot = format!("0x{}", "0".repeat(64));
    let two_slot = format!("0x{}2", "0".repeat(63));
    for (method, params, want) in [
        ("eth_chainId", "[]".to_string(), "[]".to_string()),
        ("eth_blockNumber", "[]".into(), "[]".into()),
        (
            "eth_getBlockByHash",
            format!(r#"["{h1u}",false]"#),
            format!(r#"["{h1}",false]"#),
        ),
        (
            "eth_getBlockByNumber",
            r#"["0x10",true]"#.into(),
            r#"["0x10",true]"#.into(),
        ),
        (
            "eth_getBlockByNumber",
            r#"["latest",false]"#.into(),
            r#"["0x3e8",false]"#.into(),
        ),
        (
            "eth_getBlockReceipts",
            format!(r#"["{h1u}"]"#),
            format!(r#"["{h1}"]"#),
        ),
        (
            "eth_getBlockReceipts",
            r#"["safe"]"#.into(),
            r#"["0x3de"]"#.into(),
        ),
        (
            "eth_getBlockReceipts",
            format!(r#"[{{"blockHash":"{h1}"}}]"#),
            format!(r#"["{h1}"]"#),
        ),
        (
            "eth_getBlockReceipts",
            format!(r#"[{{"requireCanonical":true,"blockHash":"{h1}"}}]"#),
            format!(r#"[{{"blockHash":"{h1}","requireCanonical":true}}]"#),
        ),
        (
            "eth_getBlockReceipts",
            r#"[{"blockNumber":"0x5"}]"#.into(),
            r#"["0x5"]"#.into(),
        ),
        (
            "eth_getTransactionByHash",
            format!(r#"["{h1}"]"#),
            format!(r#"["{h1}"]"#),
        ),
        (
            "eth_getTransactionReceipt",
            format!(r#"["{h2}"]"#),
            format!(r#"["{h2}"]"#),
        ),
        (
            "eth_getBalance",
            format!(r#"["{a1}","finalized"]"#),
            format!(r#"["{a1}","0x3d4"]"#),
        ),
        (
            "eth_getCode",
            format!(r#"["{a1}",{{"blockHash":"{h1}"}}]"#),
            format!(r#"["{a1}",{{"blockHash":"{h1}"}}]"#),
        ),
        (
            "eth_getTransactionCount",
            format!(r#"["{a1}",{{"blockHash":"{h1}","requireCanonical":false}}]"#),
            format!(r#"["{a1}",{{"blockHash":"{h1}"}}]"#),
        ),
        (
            "eth_getStorageAt",
            format!(r#"["{a1}","0x0",{{"blockNumber":"0x1"}}]"#),
            format!(r#"["{a1}","{zero_slot}","0x1"]"#),
        ),
        (
            "eth_getProof",
            format!(r#"["{a1}",["{h1}","0x2"],"latest"]"#),
            format!(r#"["{a1}",["{h1}","{two_slot}"],"0x3e8"]"#),
        ),
        (
            "eth_getProof",
            format!(r#"["{a1}",[],"0x0"]"#),
            format!(r#"["{a1}",[],"0x0"]"#),
        ),
        (
            "eth_call",
            format!(r#"[{{"data":"0xABCD","to":"{a1}"}}]"#),
            format!(r#"[{{"to":"{a1}","gas":"{GAS_CAP_HEX}","input":"0xabcd"}},"0x3e8"]"#),
        ),
        (
            "eth_createAccessList",
            format!(r#"[{{"input":"0x","to":"{a1}","from":"{a1}","value":"0x1"}},"0x5"]"#),
            format!(
                r#"[{{"from":"{a1}","to":"{a1}","gas":"{GAS_CAP_HEX}","value":"0x1","input":"0x"}},"0x5"]"#
            ),
        ),
        (
            "eth_getLogs",
            format!(
                r#"[{{"topics":["{h1}"],"address":"{a1}","toBlock":"0x2","fromBlock":"0x1"}}]"#
            ),
            format!(
                r#"[{{"fromBlock":"0x1","toBlock":"0x2","address":["{a1}"],"topics":["{h1}"]}}]"#
            ),
        ),
        (
            "eth_getLogs",
            format!(
                r#"[{{"address":["{a1}"],"topics":[["{h1}","{h2}"],null,"{h2}",null],"blockHash":"{h1}"}}]"#
            ),
            format!(
                r#"[{{"blockHash":"{h1}","address":["{a1}"],"topics":[["{h1}","{h2}"],null,"{h2}",null]}}]"#
            ),
        ),
    ] {
        assert_eq!(sent(method, &params), want, "{method} {params}");
        let r = ok(method, &params);
        assert_eq!(r.calls[0].method.name(), method);
        assert!(!r.batch);
    }
}

#[test]
fn every_method_has_exact_arity() {
    let (h1, a1) = (h(1), a(2));
    let call = format!(r#"{{"to":"{a1}"}}"#);
    // (method, the params of a valid call)
    let table: Vec<(&str, Vec<String>)> = vec![
        ("eth_chainId", vec![]),
        ("eth_blockNumber", vec![]),
        (
            "eth_getBlockByHash",
            vec![format!(r#""{h1}""#), "true".into()],
        ),
        (
            "eth_getBlockByNumber",
            vec![r#""0x1""#.into(), "false".into()],
        ),
        ("eth_getBlockReceipts", vec![r#""0x1""#.into()]),
        ("eth_getTransactionByHash", vec![format!(r#""{h1}""#)]),
        ("eth_getTransactionReceipt", vec![format!(r#""{h1}""#)]),
        (
            "eth_getBalance",
            vec![format!(r#""{a1}""#), r#""latest""#.into()],
        ),
        (
            "eth_getCode",
            vec![format!(r#""{a1}""#), r#""latest""#.into()],
        ),
        (
            "eth_getTransactionCount",
            vec![format!(r#""{a1}""#), r#""latest""#.into()],
        ),
        (
            "eth_getStorageAt",
            vec![
                format!(r#""{a1}""#),
                r#""0x0""#.into(),
                r#""latest""#.into(),
            ],
        ),
        (
            "eth_getProof",
            vec![format!(r#""{a1}""#), "[]".into(), r#""latest""#.into()],
        ),
        (
            "eth_getLogs",
            vec![format!(
                r#"{{"fromBlock":"0x1","toBlock":"0x1","address":"{a1}","topics":["{h1}"]}}"#
            )],
        ),
    ];
    for (method, params) in &table {
        let list = |v: &[String]| format!("[{}]", v.join(","));
        ok(method, &list(params));
        let mut more = params.clone();
        more.push(r#""0x1""#.into());
        assert_eq!(
            err(method, &list(&more)),
            Denied::Malformed,
            "{method} with one more param"
        );
        if !params.is_empty() {
            assert_eq!(
                err(method, &list(&params[..params.len() - 1])),
                Denied::Malformed,
                "{method} one less"
            );
        }
        // params must be an array.
        assert_eq!(
            err(method, "{}"),
            Denied::Malformed,
            "{method} params object"
        );
        assert_eq!(
            err(method, "null"),
            Denied::Malformed,
            "{method} params null"
        );
    }
    for method in ["eth_call", "eth_createAccessList"] {
        assert_eq!(
            sent(method, &format!("[{call}]")),
            format!(r#"[{{"to":"{a1}","gas":"{GAS_CAP_HEX}"}},"0x3e8"]"#)
        );
        ok(method, &format!(r#"[{call},"0x1"]"#));
        assert_eq!(err(method, "[]"), Denied::Malformed);
        // State overrides, block overrides: never, whatever they hold.
        assert_eq!(
            err(method, &format!(r#"[{call},"0x1",{{}}]"#)),
            Denied::ParamOutOfRange
        );
        assert_eq!(
            err(method, &format!(r#"[{call},"0x1",null]"#)),
            Denied::ParamOutOfRange
        );
        assert_eq!(
            err(method, &format!(r#"[{call},"0x1",{{}},{{}}]"#)),
            Denied::ParamOutOfRange
        );
        assert_eq!(
            err(method, &format!(r#"[{call},"0x1",{{}},{{}},{{}}]"#)),
            Denied::Malformed
        );
    }
}

#[test]
fn only_state_read_methods_are_allowed() {
    for set in [SR, ST] {
        for name in [
            "eth_sendRawTransaction",
            "eth_sendTransaction",
            "eth_sign",
            "eth_signTransaction",
            "eth_accounts",
            "eth_subscribe",
            "eth_newFilter",
            "eth_getFilterChanges",
            "eth_estimateGas",
            "eth_feeHistory",
            "eth_getRawTransactionByHash",
            "debug_setHead",
            "debug_getRawHeader",
            "debug_traceCall",
            "debug_traceTransaction",
            "debug_traceBlockByHash",
            "debug_executionWitness",
            "admin_addPeer",
            "personal_unlockAccount",
            "miner_start",
            "anvil_setBalance",
            "hardhat_reset",
            "evm_mine",
            "txpool_content",
            "ETH_CHAINID",
            "eth_chainid",
            "Eth_chainId",
            "eth_chainId ",
            " eth_chainId",
            "eth_chainId.",
            "eth_chainId/",
            "",
        ] {
            let json = call_json(name, "[]");
            assert_eq!(
                parse_request(json.as_bytes(), set),
                Err(Denied::MethodNotAllowed),
                "{name:?} under {set:?}"
            );
        }
        for (name, m) in STATE_READ {
            assert_eq!(m.name(), *name);
            let r = parse_request(call_json(name, "[]").as_bytes(), set);
            assert_ne!(r, Err(Denied::MethodNotAllowed), "{name}");
        }
    }
    assert!(STATE_TRACE_EXTRA
        .iter()
        .all(|n| Method::is_state_trace_extra(n.as_bytes())));
    // A raw control character inside the name is a JSON error before it is a method question.
    assert_eq!(
        raw(&call_json("eth_chainId\t", "[]")),
        Err(Denied::Malformed)
    );
    assert_eq!(
        raw(r#"{"jsonrpc":"2.0","id":1,"method":1,"params":[]}"#),
        Err(Denied::Malformed)
    );
    assert_eq!(
        raw(r#"{"jsonrpc":"2.0","id":1,"method":null,"params":[]}"#),
        Err(Denied::Malformed)
    );
    assert_eq!(
        raw(r#"{"jsonrpc":"2.0","id":1,"method":["eth_chainId"],"params":[]}"#),
        Err(Denied::Malformed)
    );
}

#[test]
fn envelope_keys_are_exact() {
    let good = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    raw(good).unwrap();
    // Any order.
    raw(r#"{"params":[],"method":"eth_chainId","id":1,"jsonrpc":"2.0"}"#).unwrap();
    for bad in [
        r#"{"id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"extra":1}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"jsonrpc":"2.0"}"#,
        r#"{"JSONRPC":"2.0","id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","ID":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"Method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method ":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"m\ethod":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method\u0000":"eth_chainId","params":[]}"#,
        // jsonrpc must be exactly the string 2.0.
        r#"{"jsonrpc":"2","id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.00","id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"1.0","id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":"2.0 ","id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":2.0,"id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":2,"id":1,"method":"eth_chainId","params":[]}"#,
        r#"{"jsonrpc":null,"id":1,"method":"eth_chainId","params":[]}"#,
    ] {
        assert_eq!(raw(bad), Err(Denied::Malformed), "{bad}");
    }
    // Escapes anywhere, even ones that decode to exactly the expected text.
    for bad in [
        j(r#"{"jsonrpc":"2.0","id":1,"§u006dethod":"eth_chainId","params":[]}"#),
        j(r#"{"§u006asonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#),
        j(r#"{"jsonrpc":"§u0032.0","id":1,"method":"eth_chainId","params":[]}"#),
        j(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chain§u0049d","params":[]}"#),
        j(r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","par§u0061ms":[]}"#),
        j(r#"{"jsonrpc":"2.0","id":1,"method":"eth§u005fchainId","params":[]}"#),
    ] {
        assert!(bad.contains("\\u00"), "{bad}");
        assert_eq!(raw(&bad), Err(Denied::Malformed), "{bad}");
    }
}

/// §11.2's example: geth matches keys case-insensitively, last match winning, so forwarding this
/// would run `debug_setHead`. Parsing refuses every such shape, so no outgoing request can exist.
#[test]
fn smuggled_methods_cannot_reach_the_node() {
    for bad in [
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","Method":"debug_setHead","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","METHOD":"debug_setHead","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","method":"debug_setHead","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"Method":"debug_setHead","params":[]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"Params":["0x0"]}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"ID":2}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],"Jsonrpc":"1.0"}"#,
        r#"[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},{"jsonrpc":"2.0","id":2,"method":"eth_chainId","Method":"debug_setHead","params":[]}]"#,
    ] {
        assert_eq!(raw(bad), Err(Denied::Malformed), "{bad}");
    }
    // A second `method` spelled with escapes: a decoding parser would see a duplicate, or a
    // case-insensitive one a second method; this one sees a malformed key.
    for bad in [
        j(
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","§u006dethod":"debug_setHead","params":[]}"#,
        ),
        j(
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","§u004dethod":"debug_setHead","params":[]}"#,
        ),
        j(
            r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","METHO§u0044":"debug_setHead","params":[]}"#,
        ),
        j(r#"{"jsonrpc":"2.0","id":1,"§u006dethod":"debug_setHead","params":[]}"#),
    ] {
        assert!(bad.contains("\\u00"), "{bad}");
        assert_eq!(raw(&bad), Err(Denied::Malformed), "{bad}");
    }
    let a1 = a(1);
    for (method, params) in [
        (
            "eth_call",
            format!(r#"[{{"to":"{a1}","To":"{}"}},"latest"]"#, a(2)),
        ),
        (
            "eth_call",
            format!(r#"[{{"to":"{a1}","data":"0x01","Data":"0x02"}},"latest"]"#),
        ),
        (
            "eth_call",
            format!(r#"[{{"to":"{a1}","data":"0x01","input":"0x01"}},"latest"]"#),
        ),
        (
            "eth_call",
            format!(r#"[{{"to":"{a1}","to":"{}"}},"latest"]"#, a(2)),
        ),
        (
            "eth_getLogs",
            format!(
                r#"[{{"fromBlock":"0x1","toBlock":"0x1","address":"{a1}","Address":"{a1}","topics":["{}"]}}]"#,
                h(1)
            ),
        ),
        (
            "eth_getBalance",
            format!(
                r#"["{a1}",{{"blockHash":"{}","BlockHash":"{}"}}]"#,
                h(1),
                h(2)
            ),
        ),
        (
            "eth_getBalance",
            format!(
                r#"["{a1}",{{"blockHash":"{}","blockHash":"{}"}}]"#,
                h(1),
                h(2)
            ),
        ),
    ] {
        assert_eq!(err(method, &params), Denied::Malformed, "{params}");
    }
    // And what is accepted goes out with exactly one `method` key per object, in any casing.
    let r = raw(r#"[{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]},{"jsonrpc":"2.0","id":"x","method":"eth_blockNumber","params":[]}]"#).unwrap();
    assert_outgoing_is_clean(&r);
}

/// What any outgoing body must look like: per call exactly the four keys (each once, in any casing),
/// a method from the list, and nothing from another namespace.
#[track_caller]
fn assert_outgoing_is_clean(r: &ParsedRequest) {
    let o = r.outgoing(&resolve, 100);
    let lower = String::from_utf8(o.to_ascii_lowercase()).unwrap();
    for key in ["\"method\"", "\"jsonrpc\"", "\"id\"", "\"params\""] {
        assert_eq!(
            lower.matches(key).count(),
            r.calls.len(),
            "{key} in {lower}"
        );
    }
    for ns in [
        "debug_",
        "admin_",
        "personal_",
        "miner_",
        "txpool_",
        "anvil_",
        "evm_",
    ] {
        assert!(!lower.contains(ns), "{lower}");
    }
    let v: serde_json::Value = serde_json::from_slice(&o).expect("outgoing is JSON");
    let objs: Vec<&serde_json::Value> = match &v {
        serde_json::Value::Array(items) => items.iter().collect(),
        one => vec![one],
    };
    assert_eq!(objs.len(), r.calls.len());
    for (i, (obj, c)) in objs.iter().zip(&r.calls).enumerate() {
        let m = obj.as_object().unwrap();
        assert_eq!(m.len(), 4);
        assert_eq!(m["jsonrpc"], "2.0");
        assert_eq!(m["id"], 100 + i as u64);
        assert_eq!(m["method"], c.method.name());
        assert!(m["params"].is_array());
    }
}

#[test]
fn ids() {
    let with_id = |id: &str| {
        raw(&format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"eth_chainId","params":[]}}"#
        ))
    };
    for (id, want) in [
        ("0", RpcId::Num(0)),
        ("7", RpcId::Num(7)),
        ("9007199254740991", RpcId::Num(MAX_ID_NUMBER)),
        (r#""""#, RpcId::Str(String::new())),
        (r#""abc""#, RpcId::Str("abc".into())),
        (
            r#"" !#$%&'()*+,-./09:;<=>?@AZ[]^_`az{|}~""#,
            RpcId::Str(" !#$%&'()*+,-./09:;<=>?@AZ[]^_`az{|}~".into()),
        ),
        (
            &format!(r#""{}""#, "x".repeat(64)),
            RpcId::Str("x".repeat(64)),
        ),
    ] {
        assert_eq!(with_id(id).unwrap().calls[0].id, want, "{id}");
    }
    for id in [
        "9007199254740992",
        "18446744073709551616",
        "-1",
        "-0",
        "01",
        "1.0",
        "1e3",
        "1E3",
        "0x1",
        "+1",
        "null",
        "true",
        "[]",
        "{}",
        &format!(r#""{}""#, "x".repeat(65)),
        r#""a\"b""#,
        r#""a\\b""#,
        &j(r#""a§u0041""#),
        &j(r#""§u0061""#),
        r#""a\nb""#,
        "\"a\tb\"",
        "\"caf\u{e9}\"",
        "\"a\x7fb\"",
        "NaN",
        "Infinity",
    ] {
        assert_eq!(with_id(id), Err(Denied::Malformed), "{id}");
    }
}

#[test]
fn json_grammar_is_strict() {
    let good = r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#;
    let pretty = "\r\n {\t\"jsonrpc\" : \"2.0\" ,\n \"id\" : 1 , \"method\" :\"eth_chainId\", \"params\" : [ ] }\n\n";
    assert_eq!(raw(pretty).unwrap(), raw(good).unwrap());
    for bad in [
        String::new(),
        " ".into(),
        format!("\u{feff}{good}"),
        format!("{good} x"),
        format!("{good}{good}"),
        format!("{good},"),
        format!("{good}\0"),
        good.trim_end_matches('}').to_string(),
        "null".into(),
        "1".into(),
        r#""eth_chainId""#.into(),
        "true".into(),
        "NaN".into(),
        "[NaN]".into(),
        "{".into(),
        "[".into(),
        "]".into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[],}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[1,]}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[,]}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]]"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId" "params":[]}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params"[]}"#.into(),
        r#"{'jsonrpc':'2.0','id':1,'method':'eth_chainId','params':[]}"#.into(),
        r#"{jsonrpc:"2.0",id:1,method:"eth_chainId",params:[]}"#.into(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]\u{a0}}".into(),
        "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_chainId\",\"params\":[]\x0b}".into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[tru]}"#.into(),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[nulll]}"#.into(),
    ] {
        assert_eq!(raw(&bad), Err(Denied::Malformed), "{bad:?}");
    }
    // Non-UTF-8 and control bytes inside strings.
    for bad in [
        &b"{\"jsonrpc\":\"2.0\xff\"}"[..],
        b"{\"jsonrpc\":\"2.\x010\"}",
        b"{\"a\nb\":1}",
    ] {
        assert_eq!(parse_request(bad, SR), Err(Denied::Malformed));
    }
    // At most 16 keys per object.
    let many: Vec<String> = (0..17).map(|i| format!(r#""k{i}":1"#)).collect();
    assert_eq!(
        raw(&format!("{{{}}}", many.join(","))),
        Err(Denied::Malformed)
    );
}

#[test]
fn depth_cap() {
    // The call object is depth 1 and `params` depth 2, so k nested arrays in params reach 1 + k.
    let nested = |k: usize| {
        format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":{}{}}}"#,
            "[".repeat(k),
            "]".repeat(k)
        )
    };
    assert_eq!(
        raw(&nested(MAX_JSON_DEPTH - 1)),
        Err(Denied::Malformed),
        "depth 32 is parsed (arity fails)"
    );
    assert_eq!(
        raw(&nested(MAX_JSON_DEPTH)),
        Err(Denied::TooDeep),
        "depth 33"
    );
    // Inside a batch the call object is depth 2.
    let batch = |k: usize| format!("[{}]", nested(k));
    assert_eq!(raw(&batch(MAX_JSON_DEPTH - 2)), Err(Denied::Malformed));
    assert_eq!(raw(&batch(MAX_JSON_DEPTH - 1)), Err(Denied::TooDeep));
    // Objects count too.
    let objs = |k: usize| {
        format!(
            "{}{}",
            r#"{"a":"#.repeat(k),
            "1".to_string() + &"}".repeat(k)
        )
    };
    assert_eq!(raw(&objs(MAX_JSON_DEPTH)), Err(Denied::Malformed));
    assert_eq!(raw(&objs(MAX_JSON_DEPTH + 1)), Err(Denied::TooDeep));
    // A depth bomb returns at once, without recursing.
    assert_eq!(raw(&"[".repeat(1_000_000)), Err(Denied::TooDeep));
    assert_eq!(raw(&r#"{"a":"#.repeat(200_000)), Err(Denied::TooDeep));
}

#[test]
fn batches() {
    let one =
        |i: usize| format!(r#"{{"jsonrpc":"2.0","id":{i},"method":"eth_chainId","params":[]}}"#);
    let batch = |n: usize| format!("[{}]", (0..n).map(one).collect::<Vec<_>>().join(","));
    let r = raw(&batch(1)).unwrap();
    assert!(r.batch);
    assert_eq!(
        out(&r, 5),
        r#"[{"jsonrpc":"2.0","id":5,"method":"eth_chainId","params":[]}]"#
    );
    let r = raw(&batch(MAX_BATCH)).unwrap();
    assert_eq!(r.calls.len(), MAX_BATCH);
    assert_eq!(raw(&batch(MAX_BATCH + 1)), Err(Denied::BatchSize));
    assert_eq!(raw("[]"), Err(Denied::BatchSize));
    assert_eq!(raw(" [ ] "), Err(Denied::BatchSize));
    assert_eq!(raw("[1]"), Err(Denied::Malformed));
    assert_eq!(
        raw(&format!("[{}]", batch(1))),
        Err(Denied::Malformed),
        "nested batch"
    );
    assert_eq!(raw(&format!("[{},null]", one(1))), Err(Denied::Malformed));
    // One bad element refuses the whole batch.
    assert_eq!(
        raw(&format!(
            r#"[{},{{"jsonrpc":"2.0","id":2,"method":"eth_sign","params":[]}}]"#,
            one(1)
        )),
        Err(Denied::MethodNotAllowed)
    );
    // Builder ids may repeat: the broker's own ids are distinct.
    let r = raw(&format!("[{},{}]", one(3), one(3))).unwrap();
    assert_eq!(
        out(&r, 10),
        r#"[{"jsonrpc":"2.0","id":10,"method":"eth_chainId","params":[]},{"jsonrpc":"2.0","id":11,"method":"eth_chainId","params":[]}]"#
    );
    // Ids wrap.
    assert_eq!(
        out(&r, u64::MAX),
        format!(
            r#"[{{"jsonrpc":"2.0","id":{},"method":"eth_chainId","params":[]}},{{"jsonrpc":"2.0","id":0,"method":"eth_chainId","params":[]}}]"#,
            u64::MAX
        )
    );
    // A single call is not framed.
    assert_eq!(
        out(&raw(&one(9)).unwrap(), 1),
        r#"{"jsonrpc":"2.0","id":1,"method":"eth_chainId","params":[]}"#
    );
}

#[test]
fn quantities_are_canonical() {
    for (q, want) in [
        ("0x0", Ok(0u64)),
        ("0x1", Ok(1)),
        ("0xa", Ok(10)),
        ("0x10", Ok(16)),
        ("0xffffffffffffffff", Ok(u64::MAX)),
        ("0x", Err(Denied::Malformed)),
        ("0x00", Err(Denied::Malformed)),
        ("0x01", Err(Denied::Malformed)),
        ("0X1", Err(Denied::Malformed)),
        ("0xA", Err(Denied::Malformed)),
        ("0xfF", Err(Denied::Malformed)),
        ("1", Err(Denied::Malformed)),
        ("x1", Err(Denied::Malformed)),
        ("0xg", Err(Denied::Malformed)),
        ("-0x1", Err(Denied::Malformed)),
        (" 0x1", Err(Denied::Malformed)),
        ("0x1 ", Err(Denied::Malformed)),
        ("0x10000000000000000", Err(Denied::ParamOutOfRange)),
        ("pending", Err(Denied::ParamOutOfRange)),
        ("earliest", Err(Denied::ParamOutOfRange)),
        ("Latest", Err(Denied::Malformed)),
        ("LATEST", Err(Denied::Malformed)),
        ("finalised", Err(Denied::Malformed)),
    ] {
        let r = p("eth_getBlockByNumber", &format!(r#"["{q}",false]"#));
        match want {
            Ok(n) => assert_eq!(
                sent("eth_getBlockByNumber", &format!(r#"["{q}",false]"#)),
                format!(r#"["0x{n:x}",false]"#)
            ),
            Err(e) => assert_eq!(r, Err(e), "{q}"),
        }
    }
    // Block numbers as JSON numbers are malformed.
    assert_eq!(err("eth_getBlockByNumber", "[1,false]"), Denied::Malformed);
    // Wide quantities (value, fees): up to 64 digits.
    let a1 = a(1);
    let q64 = format!("0x{}", "f".repeat(64));
    let q65 = format!("0x1{}", "0".repeat(64));
    ok(
        "eth_call",
        &format!(r#"[{{"to":"{a1}","value":"{q64}"}},"latest"]"#),
    );
    assert_eq!(
        err(
            "eth_call",
            &format!(r#"[{{"to":"{a1}","value":"{q65}"}},"latest"]"#)
        ),
        Denied::Malformed
    );
    assert_eq!(
        err(
            "eth_call",
            &format!(r#"[{{"to":"{a1}","value":"0x01"}},"latest"]"#)
        ),
        Denied::Malformed
    );
    assert_eq!(
        err(
            "eth_call",
            &format!(r#"[{{"to":"{a1}","value":1}},"latest"]"#)
        ),
        Denied::Malformed
    );
    assert_eq!(
        err(
            "eth_call",
            &format!(r#"[{{"to":"{a1}","value":null}},"latest"]"#)
        ),
        Denied::Malformed
    );
}

#[test]
fn data_addresses_and_hashes() {
    let lower = "0x00000000000000000000000000000000000000ab";
    for (addr, want) in [
        (lower, Ok(lower)),
        ("0x00000000000000000000000000000000000000AB", Ok(lower)),
        ("0x00000000000000000000000000000000000000aB", Ok(lower)),
        (
            "0x000000000000000000000000000000000000ab",
            Err(Denied::Malformed),
        ),
        (
            "0x0000000000000000000000000000000000000000ab",
            Err(Denied::Malformed),
        ),
        (
            "0x0000000000000000000000000000000000000ab",
            Err(Denied::Malformed),
        ),
        (
            "00000000000000000000000000000000000000ab00",
            Err(Denied::Malformed),
        ),
        (
            "0X00000000000000000000000000000000000000ab",
            Err(Denied::Malformed),
        ),
        (
            "0x00000000000000000000000000000000000000ag",
            Err(Denied::Malformed),
        ),
        ("0x", Err(Denied::Malformed)),
    ] {
        match want {
            Ok(w) => assert_eq!(
                sent("eth_getBalance", &format!(r#"["{addr}","0x1"]"#)),
                format!(r#"["{w}","0x1"]"#)
            ),
            Err(e) => assert_eq!(
                err("eth_getBalance", &format!(r#"["{addr}","0x1"]"#)),
                e,
                "{addr}"
            ),
        }
    }
    let hash_upper = h(0xab).to_uppercase().replacen("0X", "0x", 1);
    assert_eq!(
        sent("eth_getTransactionByHash", &format!(r#"["{hash_upper}"]"#)),
        format!(r#"["{}"]"#, h(0xab))
    );
    for bad in [
        &h(1)[..65],
        &format!("{}0", h(1)),
        &format!("{}00", h(1)),
        "0x",
    ] {
        assert_eq!(
            err("eth_getTransactionByHash", &format!(r#"["{bad}"]"#)),
            Denied::Malformed,
            "{bad}"
        );
    }
    // Call data: any even length, either case in, lowercase out.
    let a1 = a(1);
    for (d, want) in [
        ("0x", Some("0x")),
        ("0xAbCd", Some("0xabcd")),
        ("0x0", None),
        ("0xabc", None),
        ("abcd", None),
        ("0xzz", None),
    ] {
        let params = format!(r#"[{{"to":"{a1}","input":"{d}"}},"0x1"]"#);
        match want {
            Some(w) => assert_eq!(
                sent("eth_call", &params),
                format!(r#"[{{"to":"{a1}","gas":"{GAS_CAP_HEX}","input":"{w}"}},"0x1"]"#)
            ),
            None => assert_eq!(err("eth_call", &params), Denied::Malformed, "{d}"),
        }
    }
}

#[test]
fn storage_keys_normalise_to_32_bytes() {
    let a1 = a(1);
    let two = format!("0x{}02", "0".repeat(62));
    let two_upper_prefix = format!("0x{}02", "0".repeat(62));
    let want = sent("eth_getStorageAt", &format!(r#"["{a1}","{two}","0x1"]"#));
    assert_eq!(want, format!(r#"["{a1}","{two}","0x1"]"#));
    assert_eq!(
        sent("eth_getStorageAt", &format!(r#"["{a1}","0x2","0x1"]"#)),
        want
    );
    assert_eq!(
        sent(
            "eth_getStorageAt",
            &format!(r#"["{a1}","{two_upper_prefix}","0x1"]"#)
        ),
        want
    );
    let full = format!("0x{}", "f".repeat(64));
    assert_eq!(
        sent("eth_getStorageAt", &format!(r#"["{a1}","{full}","0x1"]"#)),
        format!(r#"["{a1}","{full}","0x1"]"#)
    );
    let big = format!("0x1{}", "0".repeat(63));
    assert_eq!(
        sent("eth_getStorageAt", &format!(r#"["{a1}","{big}","0x1"]"#)),
        format!(r#"["{a1}","{big}","0x1"]"#)
    );
    for bad in [
        "0x02",
        "0x",
        "2",
        &format!("0x1{}", "0".repeat(64)),
        &format!("0x{}", "0".repeat(63)),
    ] {
        assert_eq!(
            err("eth_getStorageAt", &format!(r#"["{a1}","{bad}","0x1"]"#)),
            Denied::Malformed,
            "{bad}"
        );
    }
}

#[test]
fn block_parameters() {
    let (a1, h1) = (a(1), h(1));
    for (block, want) in [
        (r#""0x5""#.to_string(), Ok(r#""0x5""#.to_string())),
        (r#""latest""#.into(), Ok(r#""0x3e8""#.into())),
        (r#""safe""#.into(), Ok(r#""0x3de""#.into())),
        (r#""finalized""#.into(), Ok(r#""0x3d4""#.into())),
        (r#""pending""#.into(), Err(Denied::ParamOutOfRange)),
        (r#""earliest""#.into(), Err(Denied::ParamOutOfRange)),
        (
            format!(r#"{{"blockHash":"{h1}"}}"#),
            Ok(format!(r#"{{"blockHash":"{h1}"}}"#)),
        ),
        (
            format!(r#"{{"blockHash":"{h1}","requireCanonical":true}}"#),
            Ok(format!(r#"{{"blockHash":"{h1}","requireCanonical":true}}"#)),
        ),
        (
            format!(r#"{{"blockHash":"{h1}","requireCanonical":false}}"#),
            Ok(format!(r#"{{"blockHash":"{h1}"}}"#)),
        ),
        (r#"{"blockNumber":"0x7"}"#.into(), Ok(r#""0x7""#.into())),
        (
            format!(r#"{{"blockHash":"{h1}","blockNumber":"0x7"}}"#),
            Err(Denied::Malformed),
        ),
        (
            r#"{"blockNumber":"0x7","requireCanonical":true}"#.into(),
            Err(Denied::Malformed),
        ),
        (r#"{"blockNumber":"latest"}"#.into(), Err(Denied::Malformed)),
        (r#"{"blockNumber":"0x07"}"#.into(), Err(Denied::Malformed)),
        (
            format!(r#"{{"blockHash":"{h1}","requireCanonical":"true"}}"#),
            Err(Denied::Malformed),
        ),
        (format!(r#"{{"blockhash":"{h1}"}}"#), Err(Denied::Malformed)),
        (
            format!(r#"{{"blockHash":"{h1}","x":1}}"#),
            Err(Denied::Malformed),
        ),
        ("{}".into(), Err(Denied::Malformed)),
        (format!(r#""{h1}""#), Err(Denied::Malformed)),
        ("null".into(), Err(Denied::Malformed)),
        ("5".into(), Err(Denied::Malformed)),
        ("[]".into(), Err(Denied::Malformed)),
    ] {
        let params = format!(r#"["{a1}",{block}]"#);
        match want {
            Ok(w) => assert_eq!(
                sent("eth_getBalance", &params),
                format!(r#"["{a1}",{w}]"#),
                "{block}"
            ),
            Err(e) => assert_eq!(err("eth_getBalance", &params), e, "{block}"),
        }
    }
    // eth_getBlockByNumber: a number or a tag only.
    assert_eq!(
        err(
            "eth_getBlockByNumber",
            &format!(r#"[{{"blockHash":"{h1}"}},false]"#)
        ),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockByNumber", r#"[{"blockNumber":"0x1"},false]"#),
        Denied::Malformed
    );
    // A hash where a number goes: 64 digits is out of u64 range, or non-canonical with a leading 0.
    assert_eq!(
        err("eth_getBlockByNumber", &format!(r#"["{}",false]"#, h(0x11))),
        Denied::ParamOutOfRange
    );
    assert_eq!(
        err("eth_getBlockByNumber", &format!(r#"["{h1}",false]"#)),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockByNumber", r#"["0x1","false"]"#),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockByNumber", r#"["0x1",0]"#),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockByNumber", r#"["0x1",null]"#),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockByHash", r#"["0x1",false]"#),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getBlockReceipts", r#"["pending"]"#),
        Denied::ParamOutOfRange
    );
}

#[test]
fn call_caps_and_keys() {
    let a1 = a(1);
    let with = |fields: &str| format!(r#"[{{"to":"{a1}"{fields}}},"0x1"]"#);
    let gas_of = |fields: &str| {
        let s = sent("eth_call", &with(fields));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        v[0]["gas"].as_str().unwrap().to_string()
    };
    assert_eq!(gas_of(""), GAS_CAP_HEX);
    assert_eq!(gas_of(r#","gas":"0x1c9c37f""#), "0x1c9c37f", "cap - 1");
    assert_eq!(
        gas_of(r#","gas":"0x1c9c380""#),
        GAS_CAP_HEX,
        "exactly the cap"
    );
    assert_eq!(
        gas_of(r#","gas":"0x1c9c381""#),
        GAS_CAP_HEX,
        "cap + 1 is clamped"
    );
    assert_eq!(gas_of(r#","gas":"0xffffffffffffffff""#), GAS_CAP_HEX);
    assert_eq!(
        gas_of(&format!(r#","gas":"0x{}""#, "f".repeat(64))),
        GAS_CAP_HEX
    );
    assert_eq!(gas_of(r#","gas":"0x0""#), "0x0");
    assert_eq!(gas_of(r#","gas":"0x5208""#), "0x5208");
    for bad in [r#","gas":"0x01""#, r#","gas":21000"#, r#","gas":null"#] {
        assert_eq!(err("eth_call", &with(bad)), Denied::Malformed, "{bad}");
    }
    // Fixed key order out, whatever order in.
    let all = format!(
        r#"[{{"input":"0x01","value":"0x2","maxPriorityFeePerGas":"0x3","maxFeePerGas":"0x4","gas":"0x5","to":"{a1}","from":"{}"}},"0x1"]"#,
        a(2)
    );
    assert_eq!(
        sent("eth_call", &all),
        format!(
            r#"[{{"from":"{}","to":"{a1}","gas":"0x5","maxFeePerGas":"0x4","maxPriorityFeePerGas":"0x3","value":"0x2","input":"0x01"}},"0x1"]"#,
            a(2)
        )
    );
    assert_eq!(
        sent("eth_call", &with(r#","gasPrice":"0x9","data":"0x02""#)),
        format!(r#"[{{"to":"{a1}","gas":"{GAS_CAP_HEX}","gasPrice":"0x9","input":"0x02"}},"0x1"]"#)
    );
    // An empty call object (contract creation of nothing) is fine.
    assert_eq!(
        sent("eth_call", r#"[{},"0x1"]"#),
        format!(r#"[{{"gas":"{GAS_CAP_HEX}"}},"0x1"]"#)
    );
    for bad in [
        r#","nonce":"0x1""#,
        r#","accessList":[]"#,
        r#","type":"0x2""#,
        r#","chainId":"0x1""#,
        r#","blobVersionedHashes":[]"#,
        r#","authorizationList":[]"#,
        r#","Data":"0x01""#,
        r#","INPUT":"0x01""#,
        r#","data":"0x01","input":"0x01""#,
        r#","data":"0x01","input":"0x02""#,
        r#","gasPrice":"0x1","maxFeePerGas":"0x1""#,
        r#","gasPrice":"0x1","maxPriorityFeePerGas":"0x1""#,
        r#","from":null"#,
        r#","value":"0x01""#,
    ] {
        assert_eq!(err("eth_call", &with(bad)), Denied::Malformed, "{bad}");
    }
    assert_eq!(err("eth_call", r#"[{"to":null},"0x1"]"#), Denied::Malformed);
    assert_eq!(err("eth_call", r#"["0x01","0x1"]"#), Denied::Malformed);
    assert_eq!(err("eth_call", r#"[[],"0x1"]"#), Denied::Malformed);
}

fn logs(filter: &str) -> Result<ParsedRequest, Denied> {
    p("eth_getLogs", &format!("[{filter}]"))
}

#[test]
fn get_logs_caps() {
    let (a1, h1) = (a(1), h(1));
    let tail = format!(r#""address":"{a1}","topics":["{h1}"]"#);
    let range = |from: &str, to: &str| {
        logs(&format!(
            r#"{{"fromBlock":"{from}","toBlock":"{to}",{tail}}}"#
        ))
    };
    // 10,000 blocks counted inclusively.
    range("0x0", "0x270f").unwrap();
    assert_eq!(range("0x0", "0x2710"), Err(Denied::ParamOutOfRange));
    range("0x64", "0x2773").unwrap();
    assert_eq!(range("0x64", "0x2774"), Err(Denied::ParamOutOfRange));
    range("0x5", "0x5").unwrap();
    assert_eq!(range("0x6", "0x5"), Err(Denied::ParamOutOfRange));
    range("0xffffffffffffffff", "0xffffffffffffffff").unwrap();
    assert_eq!(
        range("0x0", "0xffffffffffffffff"),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(range("pending", "0x5"), Err(Denied::ParamOutOfRange));
    assert_eq!(range("0x5", "earliest"), Err(Denied::ParamOutOfRange));
    // Missing bounds: not a concrete range.
    assert_eq!(
        logs(&format!(r#"{{"fromBlock":"0x1",{tail}}}"#)),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        logs(&format!(r#"{{"toBlock":"0x1",{tail}}}"#)),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        logs(&format!(r#"{{{tail}}}"#)),
        Err(Denied::ParamOutOfRange)
    );
    // blockHash form, alone.
    logs(&format!(r#"{{"blockHash":"{h1}",{tail}}}"#)).unwrap();
    assert_eq!(
        logs(&format!(
            r#"{{"blockHash":"{h1}","fromBlock":"0x1",{tail}}}"#
        )),
        Err(Denied::Malformed)
    );
    assert_eq!(
        logs(&format!(r#"{{"blockHash":"{h1}","toBlock":"0x1",{tail}}}"#)),
        Err(Denied::Malformed)
    );
    assert_eq!(
        logs(&format!(
            r#"{{"fromBlock":{{"blockNumber":"0x1"}},"toBlock":"0x1",{tail}}}"#
        )),
        Err(Denied::Malformed)
    );
    assert_eq!(
        logs(&format!(
            r#"{{"fromBlock":"0x1","toBlock":"0x1","limit":"0x1",{tail}}}"#
        )),
        Err(Denied::Malformed)
    );
    assert_eq!(
        logs(&format!(
            r#"{{"fromBlock":"0x1","toBlock":"0x1","FromBlock":"0x1",{tail}}}"#
        )),
        Err(Denied::Malformed)
    );

    // Tags are checked after resolution.
    let tagged = |from: &str, to: &str| range(from, to).unwrap();
    let r = tagged("finalized", "latest");
    assert_eq!(r.tags(), vec![BlockTag::Latest, BlockTag::Finalized]);
    let at = |fin: u64, latest: u64| {
        move |t: BlockTag| {
            if t == BlockTag::Finalized {
                fin
            } else {
                latest
            }
        }
    };
    assert_eq!(r.check_after_resolution(&at(0, 9_999)), Ok(()));
    assert_eq!(
        r.check_after_resolution(&at(0, 10_000)),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        r.check_after_resolution(&at(10, 9)),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(r.check_after_resolution(&at(7, 7)), Ok(()));
    let r = tagged("0x0", "latest");
    assert_eq!(r.check_after_resolution(&at(0, 9_999)), Ok(()));
    assert_eq!(
        r.check_after_resolution(&at(0, 10_000)),
        Err(Denied::ParamOutOfRange)
    );
    let r = tagged("safe", "0x2710");
    assert_eq!(r.check_after_resolution(&|_| 1), Ok(()));
    assert_eq!(
        r.check_after_resolution(&|_| 0),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        r.check_after_resolution(&|_| 10_001),
        Err(Denied::ParamOutOfRange)
    );
    // Out-of-range filters elsewhere in a batch are caught; other calls are not affected.
    let b = raw(&format!(
        r#"[{},{}]"#,
        call_json("eth_chainId", "[]"),
        call_json(
            "eth_getLogs",
            &format!(r#"[{{"fromBlock":"safe","toBlock":"latest",{tail}}}]"#)
        )
    ))
    .unwrap();
    assert_eq!(b.check_after_resolution(&resolve), Ok(()));
    assert_eq!(
        b.check_after_resolution(&|t| if t == BlockTag::Safe { 0 } else { 10_000 }),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        out(&b, 1)
            .matches("\"fromBlock\":\"0x3de\",\"toBlock\":\"0x3e8\"")
            .count(),
        1
    );
}

#[test]
fn get_logs_addresses_and_topics() {
    let (a1, h1) = (a(1), h(1));
    let f = |address: &str, topics: &str| {
        logs(&format!(
            r#"{{"fromBlock":"0x1","toBlock":"0x1","address":{address},"topics":{topics}}}"#
        ))
    };
    let addrs = |n: usize| {
        format!(
            "[{}]",
            (0..n)
                .map(|i| format!(r#""{}""#, a(i as u8)))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let hashes = |n: usize| {
        format!(
            "[{}]",
            (0..n)
                .map(|i| format!(r#""{}""#, h(i as u8)))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    let t0 = format!(r#"["{h1}"]"#);
    f(&addrs(1), &t0).unwrap();
    f(&addrs(MAX_LOG_ADDRESSES), &t0).unwrap();
    assert_eq!(
        f(&addrs(MAX_LOG_ADDRESSES + 1), &t0),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(f("[]", &t0), Err(Denied::ParamOutOfRange));
    assert_eq!(f("null", &t0), Err(Denied::ParamOutOfRange));
    assert_eq!(
        logs(&format!(
            r#"{{"fromBlock":"0x1","toBlock":"0x1","topics":{t0}}}"#
        )),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(f("1", &t0), Err(Denied::Malformed));
    assert_eq!(f(&format!(r#"["{a1}",null]"#), &t0), Err(Denied::Malformed));
    assert_eq!(f(r#"["0x01"]"#, &t0), Err(Denied::Malformed));

    let one = format!(r#""{a1}""#);
    f(&one, &format!(r#"["{h1}","{h1}","{h1}","{h1}"]"#)).unwrap();
    assert_eq!(
        f(&one, &format!(r#"["{h1}","{h1}","{h1}","{h1}","{h1}"]"#)),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        f(&one, &format!(r#"["{h1}",null,null,null,null]"#)),
        Err(Denied::ParamOutOfRange)
    );
    f(&one, &format!("[{}]", hashes(MAX_TOPIC_VALUES))).unwrap();
    assert_eq!(
        f(&one, &format!("[{}]", hashes(MAX_TOPIC_VALUES + 1))),
        Err(Denied::ParamOutOfRange)
    );
    f(
        &one,
        &format!(r#"["{h1}",null,null,{}]"#, hashes(MAX_TOPIC_VALUES)),
    )
    .unwrap();
    assert_eq!(
        f(
            &one,
            &format!(r#"["{h1}",null,null,{}]"#, hashes(MAX_TOPIC_VALUES + 1))
        ),
        Err(Denied::ParamOutOfRange)
    );
    // topic0 must be present and not null.
    for t in ["null", "[]", "[null]", "[[]]", &format!(r#"[null,"{h1}"]"#)] {
        assert_eq!(f(&one, t), Err(Denied::ParamOutOfRange), "{t}");
    }
    assert_eq!(
        logs(&format!(
            r#"{{"fromBlock":"0x1","toBlock":"0x1","address":{one}}}"#
        )),
        Err(Denied::ParamOutOfRange)
    );
    assert_eq!(
        f(&one, &format!(r#"["{h1}",[]]"#)),
        Err(Denied::ParamOutOfRange)
    );
    for t in [
        format!(r#""{h1}""#),
        format!(r#"["{h1}",1]"#),
        format!(r#"["{h1}",["{h1}",null]]"#),
        format!(r#"["{h1}",[["{h1}"]]]"#),
        r#"["0x01"]"#.into(),
    ] {
        assert_eq!(f(&one, &t), Err(Denied::Malformed), "{t}");
    }
    // Trailing nulls and single-value lists are kept as written.
    assert_eq!(
        sent(
            "eth_getLogs",
            &format!(
                r#"[{{"fromBlock":"0x1","toBlock":"0x1","address":{one},"topics":[["{h1}"],null]}}]"#
            )
        ),
        format!(
            r#"[{{"fromBlock":"0x1","toBlock":"0x1","address":["{a1}"],"topics":[["{h1}"],null]}}]"#
        )
    );
}

#[test]
fn get_proof_key_cap() {
    let a1 = a(1);
    let keys = |n: usize| {
        format!(
            "[{}]",
            (0..n)
                .map(|i| format!(r#""0x{i:x}""#))
                .collect::<Vec<_>>()
                .join(",")
        )
    };
    ok("eth_getProof", &format!(r#"["{a1}",{},"0x1"]"#, keys(0)));
    let r = ok(
        "eth_getProof",
        &format!(r#"["{a1}",{},"0x1"]"#, keys(MAX_PROOF_KEYS)),
    );
    assert_eq!(out(&r, 1).matches("\"0x00000000").count(), MAX_PROOF_KEYS);
    assert_eq!(
        err(
            "eth_getProof",
            &format!(r#"["{a1}",{},"0x1"]"#, keys(MAX_PROOF_KEYS + 1))
        ),
        Denied::ParamOutOfRange
    );
    assert_eq!(
        err("eth_getProof", &format!(r#"["{a1}","0x0","0x1"]"#)),
        Denied::Malformed
    );
    assert_eq!(
        err("eth_getProof", &format!(r#"["{a1}",null,"0x1"]"#)),
        Denied::Malformed
    );
}

#[test]
fn tags_subset_and_outgoing_fixed_point() {
    let (a1, h1) = (a(1), h(1));
    let body = format!(
        "[{},{},{},{}]",
        call_json("eth_call", &format!(r#"[{{"to":"{a1}"}}]"#)),
        call_json("eth_getBlockByNumber", r#"["finalized",false]"#),
        call_json(
            "eth_getBalance",
            &format!(r#"["{a1}",{{"blockHash":"{h1}"}}]"#)
        ),
        call_json(
            "eth_getLogs",
            &format!(
                r#"[{{"fromBlock":"safe","toBlock":"latest","address":"{a1}","topics":["{h1}"]}}]"#
            )
        ),
    );
    let r = raw(&body).unwrap();
    assert_eq!(
        r.tags(),
        vec![BlockTag::Latest, BlockTag::Safe, BlockTag::Finalized]
    );
    assert_eq!(raw(&call_json("eth_chainId", "[]")).unwrap().tags(), vec![]);
    let s = r.subset(&[2, 0]);
    assert!(s.batch);
    assert_eq!(s.calls, vec![r.calls[2].clone(), r.calls[0].clone()]);
    assert_eq!(s.tags(), vec![BlockTag::Latest]);
    let o = out(&s, 40);
    assert!(
        o.starts_with(r#"[{"jsonrpc":"2.0","id":40,"method":"eth_getBalance""#),
        "{o}"
    );
    assert!(
        o.contains(r#"{"jsonrpc":"2.0","id":41,"method":"eth_call""#),
        "{o}"
    );
    let single = raw(&call_json("eth_chainId", "[]")).unwrap();
    assert!(!single.subset(&[0]).batch);
    // The outgoing form re-parses to itself.
    for req in [&r, &s, &single] {
        let o1 = req.outgoing(&resolve, 3);
        let again = parse_request(&o1, SR).unwrap();
        assert_eq!(again.outgoing(&resolve, 3), o1);
        assert_outgoing_is_clean(req);
    }
}

#[test]
fn cache_keys_only_for_hash_pinned_calls() {
    let (a1, h1) = (a(1), h(1));
    let by_hash = format!(r#"{{"blockHash":"{h1}"}}"#);
    let call = format!(r#"{{"to":"{a1}"}}"#);
    let filter_hash = format!(r#"{{"blockHash":"{h1}","address":"{a1}","topics":["{h1}"]}}"#);
    for (method, params, cacheable) in [
        ("eth_getBlockByHash", format!(r#"["{h1}",false]"#), true),
        ("eth_getBlockReceipts", format!(r#"["{h1}"]"#), true),
        ("eth_getBlockReceipts", format!("[{by_hash}]"), true),
        ("eth_getBalance", format!(r#"["{a1}",{by_hash}]"#), true),
        ("eth_getCode", format!(r#"["{a1}",{by_hash}]"#), true),
        (
            "eth_getTransactionCount",
            format!(r#"["{a1}",{by_hash}]"#),
            true,
        ),
        (
            "eth_getStorageAt",
            format!(r#"["{a1}","0x0",{by_hash}]"#),
            true,
        ),
        ("eth_getProof", format!(r#"["{a1}",[],{by_hash}]"#), true),
        ("eth_call", format!(r#"[{call},{by_hash}]"#), true),
        (
            "eth_createAccessList",
            format!(r#"[{call},{by_hash}]"#),
            true,
        ),
        ("eth_chainId", "[]".into(), false),
        ("eth_blockNumber", "[]".into(), false),
        ("eth_getBlockByNumber", r#"["0x1",false]"#.into(), false),
        (
            "eth_getBlockByNumber",
            r#"["finalized",false]"#.into(),
            false,
        ),
        ("eth_getBlockReceipts", r#"["0x1"]"#.into(), false),
        ("eth_getBlockReceipts", r#"["latest"]"#.into(), false),
        (
            "eth_getBlockReceipts",
            format!(r#"[{{"blockHash":"{h1}","requireCanonical":true}}]"#),
            false,
        ),
        ("eth_getTransactionByHash", format!(r#"["{h1}"]"#), false),
        ("eth_getTransactionReceipt", format!(r#"["{h1}"]"#), false),
        ("eth_getBalance", format!(r#"["{a1}","0x1"]"#), false),
        ("eth_getBalance", format!(r#"["{a1}","latest"]"#), false),
        (
            "eth_getBalance",
            format!(r#"["{a1}",{{"blockNumber":"0x1"}}]"#),
            false,
        ),
        (
            "eth_getBalance",
            format!(r#"["{a1}",{{"blockHash":"{h1}","requireCanonical":true}}]"#),
            false,
        ),
        ("eth_call", format!("[{call}]"), false),
        ("eth_call", format!(r#"[{call},"safe"]"#), false),
        ("eth_getLogs", format!("[{filter_hash}]"), false),
    ] {
        let r = ok(method, &params);
        let key = r.cache_key(0);
        assert_eq!(key.is_some(), cacheable, "{method} {params}");
        if let Some(k) = key {
            let k = String::from_utf8(k).unwrap();
            assert!(
                k.starts_with(&format!(
                    r#"{{"jsonrpc":"2.0","method":"{method}","params":["#
                )),
                "{k}"
            );
            assert!(!k.contains("\"id\""), "{k}");
        }
    }
    assert_eq!(ok("eth_chainId", "[]").cache_key(1), None);
    // Equal canonical calls share a key whatever the builder's id, spelling or over-cap gas.
    let k1 = raw(&format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{{"to":"{a1}"}},{by_hash}]}}"#
    ))
    .unwrap()
    .cache_key(0);
    let k2 = raw(&format!(
        r#"{{"params":[{{"gas":"0xffffffff","to":"{}"}},{{"requireCanonical":false,"blockHash":"{}"}}],"method":"eth_call","id":"z","jsonrpc":"2.0"}}"#,
        a1.to_uppercase().replacen("0X", "0x", 1),
        h1.to_uppercase().replacen("0X", "0x", 1)
    ))
    .unwrap()
    .cache_key(0);
    assert!(k1.is_some());
    assert_eq!(k1, k2);
    // Different calls, different keys.
    let k3 = ok("eth_getBalance", &format!(r#"["{a1}",{by_hash}]"#)).cache_key(0);
    let k4 = ok("eth_getCode", &format!(r#"["{a1}",{by_hash}]"#)).cache_key(0);
    assert_ne!(k3, k4);
}

// ------------------------------------------------------------------------------------------------
// Answers.

fn envelope(id: &str, payload: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":{id},{payload}}}"#)
}

fn answer(r: &ParsedRequest, body: &str) -> Result<Vec<CallAnswer>, ResponseError> {
    parse_answers(r, body.as_bytes(), 7, usize::MAX)
}

/// The canonical form of `json` as the result of a call whose null result is an answer.
fn canon(json: &str) -> Result<String, ResponseError> {
    let r = ok("eth_getBlockByNumber", r#"["0x1",false]"#);
    answer(&r, &envelope("7", &format!(r#""result":{json}"#))).map(|a| {
        assert!(!a[0].is_error);
        String::from_utf8(a[0].canonical.clone()).unwrap()
    })
}

#[test]
fn results_are_canonical() {
    for (input, want) in [
        (r#""0x1""#, r#""0x1""#),
        ("  [ 1 , -2 ,\n\t0 ]  ", "[1,-2,0]"),
        (r#"{ "a" : { "b" : [ true , false , null ] } , "c" : "d" }"#, r#"{"a":{"b":[true,false,null]},"c":"d"}"#),
        ("{}", "{}"),
        ("[]", "[]"),
        ("[[],{}]", "[[],{}]"),
        ("123456789012345678901234567890", "123456789012345678901234567890"),
        ("-123456789012345678901234567890", "-123456789012345678901234567890"),
        // Key order is kept, not sorted.
        (r#"{"b":1,"a":2}"#, r#"{"b":1,"a":2}"#),
        // Escapes, every kind.
        (
            &j(r#""q\"b\\s\/b\bf\fn\nr\rt\tz§u0000u§u001fA§u0041e§u00E9E§u00e9s§ud83d§ude00p§u2028d§u007f""#),
            "\"q\\\"b\\\\s/b\\bf\\fn\\nr\\rt\\tz\\u0000u\\u001fAAe\u{e9}E\u{e9}s\u{1f600}p\u{2028}d\u{7f}\"",
        ),
        ("\"raw caf\u{e9} \u{1f600} \u{7f}\"", "\"raw caf\u{e9} \u{1f600} \u{7f}\""),
        (&j(r#"{"§u0061":1}"#), r#"{"a":1}"#),
        (&j(r#"{"k":"§u005c§u0022"}"#), r#"{"k":"\\\""}"#),
        (r#"{"\"":1}"#, r#"{"\"":1}"#),
    ] {
        assert_eq!(canon(input).as_deref(), Ok(want), "{input}");
    }
    for bad in [
        // Numbers: integers only.
        "1.0",
        "1e3",
        "1E3",
        "-1e-3",
        "0.5",
        ".5",
        "+1",
        "-",
        "-0",
        "01",
        "-01",
        "00",
        "1.",
        "NaN",
        "Infinity",
        "-Infinity",
        // Strings.
        r#""\ud83d""#,
        r#""\ude00""#,
        &j(r#""§ud83d§u0041""#),
        r#""\ud83dA""#,
        r#""\ud83dx""#,
        r#""\ud83d\""#,
        r#""\x41""#,
        r#""\u12""#,
        r#""\u12g4""#,
        r#""\U0041""#,
        r#""\'""#,
        "\"a\x01b\"",
        "\"a\nb\"",
        "\"a\tb\"",
        "\"abc",
        // Structure.
        "[1,]",
        "[,1]",
        "{\"a\":1,}",
        "{\"a\"}",
        "{\"a\":}",
        "{a:1}",
        "{'a':1}",
        "[1 2]",
        "{\"a\":1 \"b\":2}",
        "tru",
        "nul",
        "falsey",
        // Duplicate keys, also through escapes, at any level.
        r#"{"a":1,"a":2}"#,
        &j(r#"{"a":1,"§u0061":2}"#),
        &j(r#"{"x":{"§u0061":1,"a":1}}"#),
        r#"[{"k":1,"k":1}]"#,
    ] {
        assert_eq!(canon(bad), Err(ResponseError::Malformed), "{bad}");
    }
    // Raw bytes that are not UTF-8.
    let r = ok("eth_getBlockByNumber", r#"["0x1",false]"#);
    for bad in [
        &b"\"\xff\""[..],
        b"\"\xc3\"",
        b"\"\xc0\xaf\"",
        b"\"\xed\xa0\x80\"",
        b"\"\xf8\x88\x80\x80\x80\"",
    ] {
        let mut body = br#"{"jsonrpc":"2.0","id":7,"result":"#.to_vec();
        body.extend_from_slice(bad);
        body.push(b'}');
        assert_eq!(
            parse_answers(&r, &body, 7, usize::MAX),
            Err(ResponseError::Malformed),
            "{bad:?}"
        );
    }
}

#[test]
fn canonical_strings_match_serde_json() {
    for s in [
        "",
        "plain",
        "a\"b\\c/d",
        "\u{0}\u{1}\u{8}\u{9}\u{a}\u{b}\u{c}\u{d}\u{1f}\u{7f}",
        "caf\u{e9} \u{1f600} \u{2028}\u{fffd}",
    ] {
        let want = serde_json::to_string(s).unwrap();
        // Every char escaped as \uXXXX (surrogate pairs where needed).
        let escaped: String = s.encode_utf16().map(|u| format!("\\u{u:04X}")).collect();
        assert_eq!(canon(&format!("\"{escaped}\"")).unwrap(), want, "{s:?}");
        assert_eq!(canon(&want).unwrap(), want, "{s:?}");
    }
}

#[test]
fn response_depth() {
    // A single response object is depth 1, so k nested arrays in the result reach 1 + k.
    let nested = |k: usize| format!("{}{}", "[".repeat(k), "]".repeat(k));
    canon(&nested(MAX_JSON_DEPTH - 1)).unwrap();
    assert_eq!(
        canon(&nested(MAX_JSON_DEPTH)),
        Err(ResponseError::Malformed)
    );
    let objs = |k: usize| format!("{}1{}", r#"{"a":"#.repeat(k), "}".repeat(k));
    canon(&objs(MAX_JSON_DEPTH - 1)).unwrap();
    assert_eq!(canon(&objs(MAX_JSON_DEPTH)), Err(ResponseError::Malformed));
    // In a batch the response objects are depth 2.
    let r = raw(&format!(
        "[{}]",
        call_json("eth_getBlockByNumber", r#"["0x1",false]"#)
    ))
    .unwrap();
    let batch = |k: usize| format!("[{}]", envelope("7", &format!(r#""result":{}"#, nested(k))));
    answer(&r, &batch(MAX_JSON_DEPTH - 2)).unwrap();
    assert_eq!(
        answer(&r, &batch(MAX_JSON_DEPTH - 1)),
        Err(ResponseError::Malformed)
    );
    // Depth bombs, anywhere, including in fields that are skipped.
    assert_eq!(canon(&"[".repeat(1_000_000)), Err(ResponseError::Malformed));
    let single = ok("eth_getBlockByNumber", r#"["0x1",false]"#);
    let skipped =
        |junk: &str| format!(r#"{{"jsonrpc":"2.0","id":7,"junk":{junk},"result":"0x1"}}"#);
    answer(&single, &skipped(&nested(MAX_JSON_DEPTH - 1))).unwrap();
    assert_eq!(
        answer(&single, &skipped(&nested(MAX_JSON_DEPTH))),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        answer(&single, &skipped(&"[".repeat(100_000))),
        Err(ResponseError::Malformed)
    );
    let in_error = format!(
        r#"{{"jsonrpc":"2.0","id":7,"error":{{"code":1,"data":{}}}}}"#,
        "{\"a\":".repeat(100_000)
    );
    let single = ok("eth_chainId", "[]");
    assert_eq!(answer(&single, &in_error), Err(ResponseError::Malformed));
}

#[test]
fn huge_and_wide_values() {
    let r = ok("eth_getBlockByNumber", r#"["0x1",false]"#);
    let wide = format!("[{}]", vec!["0"; 200_000].join(", "));
    let body = envelope("7", &format!(r#""result":{wide}"#));
    let a = parse_answers(&r, body.as_bytes(), 7, usize::MAX).unwrap();
    assert_eq!(a[0].canonical.len(), 2 * 200_000 + 1);
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, 100_000),
        Err(ResponseError::TooLarge)
    );
    let long = format!("\"0x{}\"", "ab".repeat(500_000));
    let body = envelope("7", &format!(r#""result":{long}"#));
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, usize::MAX).unwrap()[0].canonical,
        long.as_bytes()
    );
    // Many keys.
    let keys: Vec<String> = (0..20_000).map(|i| format!(r#""k{i}":{i}"#)).collect();
    let obj = format!("{{{}}}", keys.join(","));
    assert_eq!(canon(&obj).unwrap(), obj);
}

#[test]
fn max_bytes_bounds_the_rendered_response() {
    let r = ok("eth_getBlockByNumber", r#"["0x1",false]"#);
    let body = envelope("7", r#""result" : { "number" : "0x1" }"#);
    let a = parse_answers(&r, body.as_bytes(), 7, usize::MAX).unwrap();
    let n = render(&r, &a).len();
    assert_eq!(
        render(&r, &a),
        br#"{"jsonrpc":"2.0","id":1,"result":{"number":"0x1"}}"#
    );
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, n).unwrap(),
        a,
        "exactly the cap"
    );
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, n - 1),
        Err(ResponseError::TooLarge),
        "one over"
    );
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, 0),
        Err(ResponseError::TooLarge)
    );
    // A batch, with an error and a string id.
    let b = raw(&format!(
        r#"[{},{{"jsonrpc":"2.0","id":"abc","method":"eth_chainId","params":[]}}]"#,
        call_json("eth_blockNumber", "[]")
    ))
    .unwrap();
    let body = format!(
        r#"[{},{}]"#,
        envelope("8", r#""error":{"code":-32000,"message":"boom"}"#),
        envelope("7", r#""result":"0x10""#)
    );
    let a = parse_answers(&b, body.as_bytes(), 7, usize::MAX).unwrap();
    let rendered = render(&b, &a);
    assert_eq!(
        rendered,
        br#"[{"jsonrpc":"2.0","id":1,"result":"0x10"},{"jsonrpc":"2.0","id":"abc","error":{"code":-32000}}]"#
    );
    // The budget counts each answer as a result (one byte more than an error), so the bound holds.
    let n = rendered.len() + 1;
    parse_answers(&b, body.as_bytes(), 7, n).unwrap();
    assert_eq!(
        parse_answers(&b, body.as_bytes(), 7, n - 1),
        Err(ResponseError::TooLarge)
    );
}

#[test]
fn envelope_rules() {
    let r = ok("eth_chainId", "[]");
    assert_eq!(
        answer(&r, &envelope("7", r#""result":"0x1""#)).unwrap()[0].canonical,
        br#""0x1""#
    );
    // Keys in any order, unknown keys ignored, whitespace anywhere.
    assert_eq!(
        answer(&r, " { \"result\" : \"0x1\" , \"x-provider\" : {\"a\":[1]} , \"id\" : 7 , \"jsonrpc\" : \"2.0\" } ").unwrap()[0].canonical,
        br#""0x1""#
    );
    for (body, want) in [
        (envelope("8", r#""result":"0x1""#), ResponseError::Mismatch),
        (envelope("6", r#""result":"0x1""#), ResponseError::Mismatch),
        (
            envelope(r#""7""#, r#""result":"0x1""#),
            ResponseError::Mismatch,
        ),
        (
            envelope("null", r#""result":"0x1""#),
            ResponseError::Mismatch,
        ),
        (envelope("-7", r#""result":"0x1""#), ResponseError::Mismatch),
        (
            envelope("18446744073709551616", r#""result":"0x1""#),
            ResponseError::Mismatch,
        ),
        (
            r#"{"jsonrpc":"2.0","result":"0x1"}"#.into(),
            ResponseError::Mismatch,
        ),
        (
            envelope("7.0", r#""result":"0x1""#),
            ResponseError::Malformed,
        ),
        (
            envelope("07", r#""result":"0x1""#),
            ResponseError::Malformed,
        ),
        (
            r#"{"id":7,"result":"0x1"}"#.into(),
            ResponseError::Malformed,
        ),
        (
            r#"{"jsonrpc":"1.0","id":7,"result":"0x1"}"#.into(),
            ResponseError::Malformed,
        ),
        (
            r#"{"jsonrpc":2.0,"id":7,"result":"0x1"}"#.into(),
            ResponseError::Malformed,
        ),
        (
            envelope("7", r#""result":"0x1","error":{"code":1}"#),
            ResponseError::Malformed,
        ),
        (
            envelope("7", r#""error":{"code":1},"result":null"#),
            ResponseError::Malformed,
        ),
        (
            envelope("7", r#""result":"0x1","result":"0x2""#),
            ResponseError::Malformed,
        ),
        (
            envelope("7", r#""result":"0x1","id":7"#),
            ResponseError::Malformed,
        ),
        (
            envelope("7", r#""x":1,"x":2,"result":"0x1""#),
            ResponseError::Malformed,
        ),
        (
            r#"{"jsonrpc":"2.0","id":7}"#.into(),
            ResponseError::Malformed,
        ),
        (r#"{}"#.into(), ResponseError::Malformed),
        (
            format!("[{}]", envelope("7", r#""result":"0x1""#)),
            ResponseError::Malformed,
        ),
        (
            format!("{} ", envelope("7", r#""result":"0x1""#)) + "x",
            ResponseError::Malformed,
        ),
        (
            format!("\u{feff}{}", envelope("7", r#""result":"0x1""#)),
            ResponseError::Malformed,
        ),
        (
            format!("{0}{0}", envelope("7", r#""result":"0x1""#)),
            ResponseError::Malformed,
        ),
        (String::new(), ResponseError::Malformed),
        ("null".into(), ResponseError::Malformed),
        (
            "<html>502 Bad Gateway</html>".into(),
            ResponseError::Malformed,
        ),
    ] {
        assert_eq!(answer(&r, &body), Err(want), "{body}");
    }
}

#[test]
fn batch_answers_are_reordered_and_matched() {
    let calls: Vec<String> = (0..5)
        .map(|i| call_json("eth_getBlockByNumber", &format!(r#"["0x{i:x}",false]"#)))
        .collect();
    let r = raw(&format!("[{}]", calls.join(","))).unwrap();
    let res = |id: u64| envelope(&id.to_string(), &format!(r#""result":"r{id}""#));
    let body = |ids: &[u64]| {
        format!(
            "[{}]",
            ids.iter().map(|&i| res(i)).collect::<Vec<_>>().join(",")
        )
    };
    let a = answer(&r, &body(&[11, 9, 7, 10, 8])).unwrap();
    let got: Vec<String> = a
        .iter()
        .map(|x| String::from_utf8(x.canonical.clone()).unwrap())
        .collect();
    assert_eq!(got, ["\"r7\"", "\"r8\"", "\"r9\"", "\"r10\"", "\"r11\""]);
    assert_eq!(
        answer(&r, &body(&[7, 8, 9, 10])),
        Err(ResponseError::Mismatch),
        "missing"
    );
    assert_eq!(
        answer(&r, &body(&[7, 8, 9, 10, 10])),
        Err(ResponseError::Mismatch),
        "duplicate"
    );
    assert_eq!(
        answer(&r, &body(&[7, 8, 9, 10, 12])),
        Err(ResponseError::Mismatch),
        "unknown"
    );
    assert_eq!(
        answer(&r, &body(&[7, 8, 9, 10, 11, 12])),
        Err(ResponseError::Mismatch),
        "extra"
    );
    assert_eq!(answer(&r, "[]"), Err(ResponseError::Mismatch));
    assert_eq!(
        answer(&r, &res(7)),
        Err(ResponseError::Malformed),
        "an object for a batch"
    );
    assert_eq!(
        answer(&r, &format!("[{},]", res(7))),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        answer(&r, &body(&[7, 8, 9, 10, 11]).replace("},{", "} {")),
        Err(ResponseError::Malformed)
    );
    // Ids that wrap around u64::MAX.
    let a = parse_answers(
        &r,
        body(&[u64::MAX, 3, 0, 1, 2]).as_bytes(),
        u64::MAX,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(a[0].canonical, format!("\"r{}\"", u64::MAX).as_bytes());
    assert_eq!(a[4].canonical, b"\"r3\"");
    // A batch of one is still an array.
    let one = raw(&format!("[{}]", calls[0])).unwrap();
    assert_eq!(
        answer(&one, &format!("[{}]", res(7))).unwrap()[0].canonical,
        b"\"r7\""
    );
    assert_eq!(answer(&one, &res(7)), Err(ResponseError::Malformed));
}

#[test]
fn error_objects_are_reduced() {
    let r = ok("eth_call", &format!(r#"[{{"to":"{}"}},"0x1"]"#, a(1)));
    let err_of = |e: &str| answer(&r, &envelope("7", &format!(r#""error":{e}"#)));
    let canon_err = |e: &str| {
        let a = err_of(e).unwrap();
        assert!(a[0].is_error);
        String::from_utf8(a[0].canonical.clone()).unwrap()
    };
    for (e, want) in [
        (
            r#"{"code":3,"message":"execution reverted: nope","data":"0x08c379a0ABCD"}"#,
            r#"{"code":3,"data":"0x08c379a0abcd"}"#,
        ),
        (
            r#"{ "data" : "0x" , "code" : -32000 }"#,
            r#"{"code":-32000,"data":"0x"}"#,
        ),
        (
            r#"{"code":-32000,"message":"out of gas"}"#,
            r#"{"code":-32000}"#,
        ),
        (r#"{"code":-32000,"data":"0xabc"}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":"0xzz"}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":"abcd"}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":"0XAB"}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":"0xab "}"#, r#"{"code":-32000}"#),
        (
            r#"{"code":-32000,"data":{"reason":"x"}}"#,
            r#"{"code":-32000}"#,
        ),
        (r#"{"code":-32000,"data":["0x01"]}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":12}"#, r#"{"code":-32000}"#),
        (r#"{"code":-32000,"data":null}"#, r#"{"code":-32000}"#),
        (
            &j(r#"{"code":-32000,"data":"§u0030x§u0041b"}"#),
            r#"{"code":-32000,"data":"0xab"}"#,
        ),
        (
            r#"{"code":-32000,"message":{"nested":"text"}}"#,
            r#"{"code":-32000}"#,
        ),
        (
            r#"{"code":-32000,"message":null,"extra":[1,2]}"#,
            r#"{"code":-32000}"#,
        ),
        (r#"{"code":0}"#, r#"{"code":0}"#),
        (
            r#"{"code":-9223372036854775808}"#,
            r#"{"code":-9223372036854775808}"#,
        ),
        (
            r#"{"code":9223372036854775807}"#,
            r#"{"code":9223372036854775807}"#,
        ),
    ] {
        assert_eq!(canon_err(e), want, "{e}");
    }
    for e in [
        r#"{"message":"no code"}"#,
        r#"{"code":"-32000"}"#,
        r#"{"code":-32000.0}"#,
        r#"{"code":-3e4}"#,
        r#"{"code":null}"#,
        r#"{"code":9223372036854775808}"#,
        r#"{"code":-9223372036854775809}"#,
        r#"{"code":1,"code":2}"#,
        r#"{"code":1,"data":"0x01","data":"0x02"}"#,
        r#"{"code":1,"message":"a","message":"b"}"#,
        r#""just a string""#,
        "null",
        "[]",
        r#"{"code":1,}"#,
    ] {
        assert_eq!(err_of(e), Err(ResponseError::Malformed), "{e}");
    }
    // The message never reaches the builder.
    let a = err_of(r#"{"code":-32000,"message":"secret http://10.0.0.1:8545/key"}"#).unwrap();
    assert_eq!(a[0].canonical, br#"{"code":-32000}"#);
}

#[test]
fn lagging_errors() {
    let r = ok("eth_getBalance", &format!(r#"["{}","0x1"]"#, a(1)));
    let with = |code: i64, msg: &str| {
        answer(
            &r,
            &envelope(
                "7",
                &format!(r#""error":{{"code":{code},"message":"{msg}"}}"#),
            ),
        )
    };
    for msg in LAGGING_MESSAGES {
        assert_eq!(with(-32000, msg), Err(ResponseError::Lagging), "{msg}");
        assert_eq!(
            with(-32000, &msg.to_uppercase()),
            Err(ResponseError::Lagging),
            "{msg}"
        );
        assert_eq!(
            with(-32000, &format!("prefix: {msg} (more)")),
            Err(ResponseError::Lagging),
            "{msg}"
        );
        // A reverted call chooses its own reason: never lagging.
        assert!(
            with(-32000, &format!("execution reverted: {msg}")).is_ok(),
            "{msg}"
        );
        assert!(with(3, msg).is_ok(), "{msg}");
        assert!(with(-32000, &format!("Reverted {msg}")).is_ok(), "{msg}");
    }
    for (code, msg) in [
        (
            -32000,
            "missing trie node 7c2f2b2f (path ) state 0x1 is not available",
        ),
        (-32000, "state at block #12 is pruned"),
        (-32000, "historical state 0xabc is not available"),
        (-32000, "safe block not found"),
        (-32000, "pruned history unavailable"),
        (-32000, "header\\u0020not found"),
    ] {
        assert_eq!(with(code, msg), Err(ResponseError::Lagging), "{msg}");
    }
    for msg in [
        "execution reverted",
        "out of gas",
        "invalid opcode: INVALID",
        "insufficient funds",
        "rate limited",
        "",
        "header found",
    ] {
        let a = with(-32000, msg).unwrap();
        assert!(a[0].is_error, "{msg}");
    }
    // In a batch, one lagging answer sends the whole response elsewhere.
    let b = raw(&format!(
        "[{},{}]",
        call_json("eth_chainId", "[]"),
        call_json("eth_blockNumber", "[]")
    ))
    .unwrap();
    let body = format!(
        "[{},{}]",
        envelope("7", r#""result":"0x1""#),
        envelope(
            "8",
            r#""error":{"code":-32000,"message":"header not found"}"#
        )
    );
    assert_eq!(answer(&b, &body), Err(ResponseError::Lagging));
}

/// Review F5 (the reviewer's PoC, inverted): "I lack that block" errors that are not in
/// `LAGGING_MESSAGES` — geth's unknown EIP-1898 hash, erigon's "block … not found", EIP-1474's
/// -32001 — are lagging for a pinned call; any other non-revert error on a pinned call is suspect.
#[test]
fn not_found_errors_on_pinned_calls_are_lagging() {
    let by_hash = ok("eth_getBalance", &format!(r#"["{}",{{"blockHash":"{}"}}]"#, a(1), h(0x11)));
    let by_num = ok("eth_getBalance", &format!(r#"["{}","0x5"]"#, a(1)));
    let by_tag = ok("eth_call", &format!(r#"[{{"to":"{}"}},"safe"]"#, a(1)));
    let unpinned = ok("eth_getTransactionReceipt", &format!(r#"["{}"]"#, h(1)));
    let with = |r: &ParsedRequest, code: i64, msg: &str| {
        answer(r, &envelope("7", &format!(r#""error":{{"code":{code},"message":"{msg}"}}"#)))
    };
    for (code, msg) in [
        (-32000, "header for hash not found"),
        (-32000, "block 0x1111 not found"),
        (-32001, "Resource not found"),
        (-32001, ""),
        (-32000, "Block with hash 0x11 was NOT FOUND"),
    ] {
        for r in [&by_hash, &by_num, &by_tag] {
            assert_eq!(with(r, code, msg), Err(ResponseError::Lagging), "{code} {msg}");
        }
        let a = with(&unpinned, code, msg).unwrap();
        assert!(a[0].is_error && !a[0].suspect, "not pinned: an answer ({msg})");
        // A revert chooses its own reason: never lagging, never suspect.
        for (c, m) in [(3, msg.to_string()), (-32000, format!("execution reverted: {msg}"))] {
            let a = with(&by_hash, c, &m).unwrap();
            assert!(a[0].is_error && !a[0].suspect, "{c} {m}");
        }
    }
    // Any other error on a pinned call is suspect (the broker checks the endpoint's head).
    let a = with(&by_num, -32602, "BlockOutOfRangeError: block height is 0 but requested was 5").unwrap();
    assert!(a[0].is_error && a[0].suspect);
    assert!(with(&by_hash, -32000, "out of gas").unwrap()[0].suspect);
    assert!(with(&by_num, -32000, "not found: header").unwrap()[0].suspect, "the subject comes first");
    assert!(!with(&unpinned, -32602, "x").unwrap()[0].suspect);
    // Successful answers are never suspect.
    assert!(!answer(&by_num, &envelope("7", r#""result":"0x0""#)).unwrap()[0].suspect);
    // A tag query reads -32001 as lagging too.
    assert_eq!(
        parse_tag_answer(br#"{"jsonrpc":"2.0","id":9,"error":{"code":-32001,"message":"x"}}"#, 9),
        Err(ResponseError::Lagging)
    );
}

#[test]
fn pins_and_explicit_numbers() {
    let hash = |b: u8| [b; 32];
    let r = raw(&format!(
        "[{}]",
        [
            call_json("eth_chainId", "[]"),
            call_json("eth_getBalance", &format!(r#"["{}","0x5"]"#, a(1))),
            call_json("eth_getCode", &format!(r#"["{}",{{"blockHash":"{}"}}]"#, a(1), h(0x11))),
            call_json("eth_call", &format!(r#"[{{"to":"{}"}}]"#, a(1))),
            call_json("eth_getLogs", &format!(r#"[{{"fromBlock":"0x10","toBlock":"latest","address":"{}","topics":["{}"]}}]"#, a(1), h(1))),
            call_json("eth_getBlockByHash", &format!(r#"["{}",false]"#, h(0x22))),
            call_json("eth_getTransactionByHash", &format!(r#"["{}"]"#, h(3))),
            call_json("eth_getStorageAt", &format!(r#"["{}","0x0",{{"blockNumber":"0x30"}}]"#, a(1))),
            call_json("eth_getLogs", &format!(r#"[{{"blockHash":"{}","address":"{}","topics":["{}"]}}]"#, h(0x33), a(1), h(1))),
        ]
        .join(",")
    ))
    .unwrap();
    let pins: Vec<_> = (0..r.calls.len()).map(|i| r.pin(i, &resolve)).collect();
    assert_eq!(
        pins,
        vec![
            None,
            Some(BlockPin::Number(5)),
            Some(BlockPin::Hash(hash(0x11))),
            Some(BlockPin::Number(LATEST)),
            Some(BlockPin::Number(LATEST)),
            Some(BlockPin::Hash(hash(0x22))),
            None,
            Some(BlockPin::Number(0x30)),
            Some(BlockPin::Hash(hash(0x33))),
        ]
    );
    assert_eq!(r.max_block_number(), Some(0x30));
    assert_eq!(ok("eth_getBalance", &format!(r#"["{}","latest"]"#, a(1))).max_block_number(), None);
    assert_eq!(ok("eth_chainId", "[]").max_block_number(), None);
}

#[test]
fn null_results() {
    let (a1, h1) = (a(1), h(1));
    let by_hash = format!(r#"{{"blockHash":"{h1}"}}"#);
    for (method, params, null_ok) in [
        ("eth_getTransactionByHash", format!(r#"["{h1}"]"#), true),
        ("eth_getTransactionReceipt", format!(r#"["{h1}"]"#), true),
        (
            "eth_getBlockByNumber",
            r#"["0x10",false]"#.to_string(),
            true,
        ),
        ("eth_getBlockReceipts", r#"["0x10"]"#.into(), true),
        (
            "eth_getBlockReceipts",
            r#"[{"blockNumber":"0x10"}]"#.into(),
            true,
        ),
        ("eth_getBlockByNumber", r#"["latest",false]"#.into(), false),
        (
            "eth_getBlockByNumber",
            r#"["finalized",true]"#.into(),
            false,
        ),
        ("eth_getBlockReceipts", r#"["safe"]"#.into(), false),
        ("eth_getBlockReceipts", format!(r#"["{h1}"]"#), false),
        ("eth_getBlockByHash", format!(r#"["{h1}",false]"#), false),
        ("eth_getBalance", format!(r#"["{a1}","0x1"]"#), false),
        ("eth_getCode", format!(r#"["{a1}",{by_hash}]"#), false),
        (
            "eth_getStorageAt",
            format!(r#"["{a1}","0x0","latest"]"#),
            false,
        ),
        (
            "eth_getTransactionCount",
            format!(r#"["{a1}","0x1"]"#),
            false,
        ),
        ("eth_getProof", format!(r#"["{a1}",[],"0x1"]"#), false),
        ("eth_call", format!(r#"[{{"to":"{a1}"}}]"#), false),
        (
            "eth_createAccessList",
            format!(r#"[{{"to":"{a1}"}},"0x1"]"#),
            false,
        ),
        (
            "eth_getLogs",
            format!(r#"[{{"blockHash":"{h1}","address":"{a1}","topics":["{h1}"]}}]"#),
            false,
        ),
        ("eth_chainId", "[]".into(), false),
        ("eth_blockNumber", "[]".into(), false),
    ] {
        let r = ok(method, &params);
        let got = answer(&r, &envelope("7", r#""result":null"#));
        if null_ok {
            assert_eq!(got.unwrap()[0].canonical, b"null", "{method} {params}");
        } else {
            assert_eq!(got, Err(ResponseError::Lagging), "{method} {params}");
        }
    }
}

#[test]
fn mempool_transactions_become_null() {
    let h1 = h(1);
    let r = ok("eth_getTransactionByHash", &format!(r#"["{h1}"]"#));
    let res = |obj: &str| {
        let a = answer(&r, &envelope("7", &format!(r#""result":{obj}"#))).unwrap();
        String::from_utf8(a[0].canonical.clone()).unwrap()
    };
    assert_eq!(
        res(r#"{"hash":"0x1","blockHash":null,"blockNumber":null}"#),
        "null"
    );
    assert_eq!(res(r#"{ "hash" : "0x1" , "blockHash" : null }"#), "null");
    assert_eq!(res(r#"{"blockHash":null}"#), "null");
    assert_eq!(
        res(r#"{"hash":"0x1"}"#),
        "null",
        "no blockHash at all is pending too"
    );
    assert_eq!(res("{}"), "null");
    assert_eq!(
        res(&j(r#"{"bl§u006fckHash":null}"#)),
        "null",
        "the key is compared decoded"
    );
    assert_eq!(res(&j(r#"{"blockHash":null,"x":"§u0041"}"#)), "null");
    let mined = format!(r#"{{"hash":"0x1","blockHash":"{h1}","blockNumber":"0x5"}}"#);
    assert_eq!(res(&mined), mined);
    let nested = format!(r#"{{"x":{{"blockHash":null}},"blockHash":"{h1}"}}"#);
    assert_eq!(res(&nested), nested, "only the top-level blockHash counts");
    let wrapped = format!(r#"{{"blockHashes":null,"blockHash":"{h1}"}}"#);
    assert_eq!(res(&wrapped), wrapped);
    assert_eq!(res("null"), "null");
    // Only eth_getTransactionByHash.
    let rr = ok("eth_getTransactionReceipt", &format!(r#"["{h1}"]"#));
    let a = answer(&rr, &envelope("7", r#""result":{"blockHash":null}"#)).unwrap();
    assert_eq!(a[0].canonical, br#"{"blockHash":null}"#);
    // While streaming, the object is charged at its full size (18 bytes, 14 more than `null`).
    let body = envelope("7", r#""result":{"blockHash":null}"#);
    let a = answer(&r, &body).unwrap();
    let n = render(&r, &a).len();
    assert_eq!(parse_answers(&r, body.as_bytes(), 7, n + 14).unwrap(), a);
    assert_eq!(
        parse_answers(&r, body.as_bytes(), 7, n + 13),
        Err(ResponseError::TooLarge)
    );
}

#[test]
fn render_and_tags() {
    let r = raw(r#"{"jsonrpc":"2.0","id":"q-1","method":"eth_chainId","params":[]}"#).unwrap();
    let a = answer(&r, &envelope("7", r#""result":"0x2105""#)).unwrap();
    assert_eq!(
        render(&r, &a),
        br#"{"jsonrpc":"2.0","id":"q-1","result":"0x2105"}"#
    );
    let e = answer(
        &r,
        &envelope("7", r#""error":{"code":-32601,"message":"x"}"#),
    )
    .unwrap();
    assert_eq!(
        render(&r, &e),
        br#"{"jsonrpc":"2.0","id":"q-1","error":{"code":-32601}}"#
    );
    // A constructed id that needs escapes is still rendered as valid JSON.
    let mut odd = r.clone();
    odd.calls[0].id = RpcId::Str("a\"b\\c\n".into());
    assert_eq!(
        render(&odd, &a),
        br#"{"jsonrpc":"2.0","id":"a\"b\\c\n","result":"0x2105"}"#
    );
    // tag_query / parse_tag_answer.
    assert_eq!(
        tag_query(BlockTag::Safe, 9),
        br#"{"jsonrpc":"2.0","id":9,"method":"eth_getBlockByNumber","params":["safe",false]}"#
    );
    assert_eq!(
        tag_query(BlockTag::Latest, 0),
        br#"{"jsonrpc":"2.0","id":0,"method":"eth_getBlockByNumber","params":["latest",false]}"#
    );
    assert_eq!(
        tag_query(BlockTag::Finalized, 1),
        br#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}"#
    );
    // The tag query is itself a valid builder request.
    parse_request(&tag_query(BlockTag::Finalized, 1), SR).unwrap();
    let block = |n: &str| {
        format!(
            r#"{{"jsonrpc":"2.0","id":9,"result":{{"hash":"{}","number":{n},"transactions":["{}"]}}}}"#,
            h(1),
            h(2)
        )
    };
    assert_eq!(
        parse_tag_answer(block(r#""0x12a05f200""#).as_bytes(), 9),
        Ok(5_000_000_000)
    );
    assert_eq!(parse_tag_answer(block(r#""0x0""#).as_bytes(), 9), Ok(0));
    assert_eq!(
        parse_tag_answer(block(r#""0xABC""#).as_bytes(), 9),
        Ok(0xabc)
    );
    assert_eq!(
        parse_tag_answer(block(r#""0xffffffffffffffff""#).as_bytes(), 9),
        Ok(u64::MAX)
    );
    assert_eq!(
        parse_tag_answer(block(r#""0x1""#).as_bytes(), 8),
        Err(ResponseError::Mismatch)
    );
    for bad in [
        r#""0x""#,
        r#""0x10000000000000000""#,
        r#""12""#,
        "12",
        "null",
        r#""0xg""#,
    ] {
        assert_eq!(
            parse_tag_answer(block(bad).as_bytes(), 9),
            Err(ResponseError::Malformed),
            "{bad}"
        );
    }
    assert_eq!(
        parse_tag_answer(br#"{"jsonrpc":"2.0","id":9,"result":{"hash":"0x1"}}"#, 9),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        parse_tag_answer(br#"{"jsonrpc":"2.0","id":9,"result":"0x5"}"#, 9),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        parse_tag_answer(br#"{"jsonrpc":"2.0","id":9,"result":null}"#, 9),
        Err(ResponseError::Lagging)
    );
    assert_eq!(
        parse_tag_answer(br#"{"jsonrpc":"2.0","id":9,"error":{"code":-32000,"message":"finalized block not found"}}"#, 9),
        Err(ResponseError::Lagging)
    );
    assert_eq!(
        parse_tag_answer(
            br#"{"jsonrpc":"2.0","id":9,"error":{"code":-32601,"message":"method not found"}}"#,
            9
        ),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        parse_tag_answer(br#"[{"jsonrpc":"2.0","id":9,"result":null}]"#, 9),
        Err(ResponseError::Malformed)
    );
    assert_eq!(
        parse_tag_answer(format!("{} x", block(r#""0x1""#)).as_bytes(), 9),
        Err(ResponseError::Malformed)
    );
}

// ------------------------------------------------------------------------------------------------
// Fuzzing.

fn hex_case(bytes: &[u8], upper: bool) -> String {
    let s = hex::encode(bytes);
    format!("0x{}", if upper { s.to_uppercase() } else { s })
}

fn hash_s() -> impl Strategy<Value = String> {
    (prop::array::uniform32(any::<u8>()), any::<bool>())
        .prop_map(|(b, u)| format!(r#""{}""#, hex_case(&b, u)))
}

fn addr_s() -> impl Strategy<Value = String> {
    (prop::array::uniform20(any::<u8>()), any::<bool>())
        .prop_map(|(b, u)| format!(r#""{}""#, hex_case(&b, u)))
}

fn qty_s() -> impl Strategy<Value = String> {
    any::<u64>().prop_map(|n| format!(r#""0x{n:x}""#))
}

fn tag_s() -> impl Strategy<Value = String> {
    prop::sample::select(vec![r#""latest""#, r#""safe""#, r#""finalized""#])
        .prop_map(str::to_string)
}

fn block_state_s() -> impl Strategy<Value = String> {
    prop_oneof![
        qty_s(),
        tag_s(),
        hash_s().prop_map(|h| format!(r#"{{"blockHash":{h}}}"#)),
        (hash_s(), any::<bool>())
            .prop_map(|(h, c)| format!(r#"{{"requireCanonical":{c},"blockHash":{h}}}"#)),
        qty_s().prop_map(|q| format!(r#"{{"blockNumber":{q}}}"#)),
    ]
}

fn storage_key_s() -> impl Strategy<Value = String> {
    prop_oneof![hash_s(), qty_s()]
}

fn call_obj_s() -> impl Strategy<Value = String> {
    (
        prop::option::of(addr_s()),
        prop::option::of(addr_s()),
        prop::option::of(any::<u64>()),
        prop::option::of(qty_s()),
        prop::option::of(prop::collection::vec(any::<u8>(), 0..40)),
        any::<bool>(),
    )
        .prop_flat_map(|(from, to, gas, value, input, data_key)| {
            let mut kv: Vec<String> = Vec::new();
            if let Some(f) = from {
                kv.push(format!(r#""from":{f}"#));
            }
            if let Some(t) = to {
                kv.push(format!(r#""to":{t}"#));
            }
            if let Some(g) = gas {
                kv.push(format!(r#""gas":"0x{g:x}""#));
            }
            if let Some(v) = value {
                kv.push(format!(r#""value":{v}"#));
            }
            if let Some(i) = input {
                kv.push(format!(
                    r#""{}":"0x{}""#,
                    if data_key { "data" } else { "input" },
                    hex::encode(i)
                ));
            }
            Just(kv)
                .prop_shuffle()
                .prop_map(|kv| format!("{{{}}}", kv.join(",")))
        })
}

fn topic_s(first: bool) -> BoxedStrategy<String> {
    let one = hash_s();
    let list = prop::collection::vec(hash_s(), 1..=MAX_TOPIC_VALUES)
        .prop_map(|v| format!("[{}]", v.join(",")));
    if first {
        prop_oneof![one, list].boxed()
    } else {
        prop_oneof![Just("null".to_string()), one, list].boxed()
    }
}

fn filter_s() -> impl Strategy<Value = String> {
    let range = prop_oneof![
        (0u64..1 << 40, 0..MAX_LOG_RANGE)
            .prop_map(|(f, d)| format!(r#""fromBlock":"0x{f:x}","toBlock":"0x{:x}""#, f + d)),
        (tag_s(), tag_s()).prop_map(|(f, t)| format!(r#""fromBlock":{f},"toBlock":{t}"#)),
        hash_s().prop_map(|h| format!(r#""blockHash":{h}"#)),
    ];
    let address = prop_oneof![
        addr_s(),
        prop::collection::vec(addr_s(), 1..=MAX_LOG_ADDRESSES)
            .prop_map(|v| format!("[{}]", v.join(","))),
    ];
    let topics = (
        topic_s(true),
        prop::collection::vec(topic_s(false), 0..MAX_TOPIC_POSITIONS),
    )
        .prop_map(|(t0, rest)| {
            format!(
                "[{}]",
                std::iter::once(t0)
                    .chain(rest)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        });
    (range, address, topics).prop_flat_map(|(r, a, t)| {
        Just(vec![
            r,
            format!(r#""address":{a}"#),
            format!(r#""topics":{t}"#),
        ])
        .prop_shuffle()
        .prop_map(|kv| format!("{{{}}}", kv.join(",")))
    })
}

fn call_s() -> impl Strategy<Value = (String, String)> {
    let m = |s: &'static str| Just(s.to_string());
    prop_oneof![
        m("eth_chainId").prop_map(|m| (m, "[]".to_string())),
        m("eth_blockNumber").prop_map(|m| (m, "[]".to_string())),
        (hash_s(), any::<bool>())
            .prop_map(|(h, f)| ("eth_getBlockByHash".into(), format!("[{h},{f}]"))),
        (prop_oneof![qty_s(), tag_s()], any::<bool>())
            .prop_map(|(b, f)| ("eth_getBlockByNumber".into(), format!("[{b},{f}]"))),
        prop_oneof![block_state_s(), hash_s()]
            .prop_map(|b| ("eth_getBlockReceipts".into(), format!("[{b}]"))),
        (
            prop::sample::select(vec![
                "eth_getTransactionByHash",
                "eth_getTransactionReceipt"
            ]),
            hash_s()
        )
            .prop_map(|(m, h)| (m.to_string(), format!("[{h}]"))),
        (
            prop::sample::select(vec![
                "eth_getBalance",
                "eth_getCode",
                "eth_getTransactionCount"
            ]),
            addr_s(),
            block_state_s()
        )
            .prop_map(|(m, a, b)| (m.to_string(), format!("[{a},{b}]"))),
        (addr_s(), storage_key_s(), block_state_s())
            .prop_map(|(a, k, b)| ("eth_getStorageAt".into(), format!("[{a},{k},{b}]"))),
        (
            addr_s(),
            prop::collection::vec(storage_key_s(), 0..6),
            block_state_s()
        )
            .prop_map(|(a, k, b)| (
                "eth_getProof".into(),
                format!("[{a},[{}],{b}]", k.join(","))
            )),
        (
            prop::sample::select(vec!["eth_call", "eth_createAccessList"]),
            call_obj_s(),
            prop::option::of(block_state_s())
        )
            .prop_map(|(m, c, b)| (
                m.to_string(),
                match b {
                    Some(b) => format!("[{c},{b}]"),
                    None => format!("[{c}]"),
                }
            )),
        filter_s().prop_map(|f| ("eth_getLogs".into(), format!("[{f}]"))),
    ]
}

fn id_s() -> impl Strategy<Value = String> {
    prop_oneof![
        (0..=MAX_ID_NUMBER).prop_map(|n| n.to_string()),
        // Printable ASCII without `"` and `\` (and without `,` and `:`, which `request_s` pads).
        r"[ !#-+\x2d-9;-\x5b\x5d-~]{0,64}".prop_map(|s| format!(r#""{s}""#)),
    ]
}

fn object_s() -> impl Strategy<Value = String> {
    (call_s(), id_s()).prop_flat_map(|((method, params), id)| {
        Just(vec![
            r#""jsonrpc":"2.0""#.to_string(),
            format!(r#""id":{id}"#),
            format!(r#""method":"{method}""#),
            format!(r#""params":{params}"#),
        ])
        .prop_shuffle()
        .prop_map(|kv| format!("{{{}}}", kv.join(",")))
    })
}

fn request_s() -> impl Strategy<Value = String> {
    (
        prop_oneof![
            object_s(),
            prop::collection::vec(object_s(), 1..=6).prop_map(|v| format!("[{}]", v.join(","))),
        ],
        any::<bool>(),
    )
        // Optional whitespace (strings hold no `,` or `:`, so this never touches them).
        .prop_map(|(s, pretty)| {
            if pretty {
                format!(" {} \n", s.replace(',', ", ").replace(':', " : "))
            } else {
                s
            }
        })
}

fn whitespace_outside_strings(json: &str) -> bool {
    let (mut in_str, mut esc) = (false, false);
    for c in json.chars() {
        match (in_str, esc, c) {
            (true, true, _) => esc = false,
            (true, false, '\\') => esc = true,
            (true, false, '"') => in_str = false,
            (true, false, _) => {}
            (false, _, '"') => in_str = true,
            (false, _, c) if c.is_whitespace() => return true,
            (false, _, _) => {}
        }
    }
    false
}

/// The fixed-point property of `outgoing`, for a request whose tags resolve to a valid getLogs range
/// (the broker calls `check_after_resolution` first; a range that resolves out of bounds would not
/// re-parse, and must not be sent).
fn check_fixed_point(r: &ParsedRequest, first_id: u64) -> Result<(), TestCaseError> {
    let o = r.outgoing(&resolve, first_id);
    let again = parse_request(&o, SR);
    match r.check_after_resolution(&resolve) {
        Ok(()) => {
            let again = again.map_err(|e| {
                TestCaseError::fail(format!("{e:?}: {}", String::from_utf8_lossy(&o)))
            })?;
            prop_assert_eq!(&again.outgoing(&resolve, first_id), &o);
            for i in 0..r.calls.len() {
                prop_assert_eq!(r.cache_key(i), again.cache_key(i));
            }
        }
        Err(e) => prop_assert_eq!(again, Err(e)),
    }
    Ok(())
}

/// A JSON string literal for `s`, each char raw or `\u`-escaped per `esc`.
fn json_str(s: &str, esc: &[bool]) -> String {
    let mut o = String::from("\"");
    for (i, c) in s.chars().enumerate() {
        let e = !esc.is_empty() && esc[i % esc.len()];
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str(if e { "\\u005C" } else { "\\\\" }),
            c if (c as u32) < 0x20 || e => {
                for u in c.encode_utf16(&mut [0; 2]) {
                    o.push_str(&format!("\\u{u:04x}"));
                }
            }
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn json_value_s() -> impl Strategy<Value = String> {
    let string = (any::<String>(), prop::collection::vec(any::<bool>(), 0..4))
        .prop_map(|(s, e)| json_str(&s, &e));
    let leaf = prop_oneof![
        Just("null".to_string()),
        Just("true".to_string()),
        Just("false".to_string()),
        any::<i64>().prop_map(|n| n.to_string()),
        string,
    ];
    leaf.prop_recursive(6, 96, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..8)
                .prop_map(|v| format!("[ {} ]", v.join(" ,"))),
            (
                prop::collection::vec(inner, 0..8),
                prop::collection::vec(any::<bool>(), 1..3)
            )
                .prop_map(|(v, e)| {
                    let fields: Vec<String> = v
                        .iter()
                        .enumerate()
                        .map(|(i, x)| format!("{} : {x}", json_str(&format!("k{i}é"), &e)))
                        .collect();
                    format!("{{{}}}", fields.join(","))
                }),
        ]
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2_000, ..ProptestConfig::default() })]

    #[test]
    fn parse_request_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400)) {
        let _ = parse_request(&bytes, SR);
        let _ = parse_request(&bytes, ST);
    }

    #[test]
    fn parse_request_never_panics_on_json_shaped_input(s in "[\\[\\]{}\",:0-9a-zA-Z_ \\\\.-]{0,200}") {
        let _ = parse_request(s.as_bytes(), SR);
    }

    #[test]
    fn valid_requests_parse_and_go_out_deterministically(s in request_s(), first_id in 0u64..1 << 40) {
        let r = parse_request(s.as_bytes(), SR).map_err(|e| TestCaseError::fail(format!("{e:?}: {s}")))?;
        let r2 = parse_request(s.as_bytes(), SR).unwrap();
        prop_assert_eq!(&r, &r2);
        let o = r.outgoing(&resolve, first_id);
        prop_assert_eq!(&o, &r2.outgoing(&resolve, first_id));
        // The outgoing form is a fixed point of parse + outgoing, with the same cache keys.
        check_fixed_point(&r, first_id)?;
        assert_outgoing_is_clean(&r);
    }

    #[test]
    fn mutated_requests_never_panic_and_stay_clean(
        s in request_s(),
        edits in prop::collection::vec((any::<prop::sample::Index>(), any::<u8>(), 0u8..3), 1..6),
    ) {
        let mut b = s.into_bytes();
        for (at, byte, kind) in edits {
            if b.is_empty() { break; }
            let i = at.index(b.len());
            match kind {
                0 => b[i] = byte,
                1 => b.insert(i, byte),
                _ => { b.remove(i); }
            }
        }
        if let Ok(r) = parse_request(&b, SR) {
            prop_assert_eq!(r.outgoing(&resolve, 1), r.outgoing(&resolve, 1));
            check_fixed_point(&r, 1)?;
            assert_outgoing_is_clean(&r);
        }
    }

    /// Any case variant of an envelope key added to a valid object is refused (`{"method":…,
    /// "Method":…}` and friends).
    #[test]
    fn case_variant_keys_are_refused(
        obj in object_s(),
        key in prop::sample::select(vec!["jsonrpc", "id", "method", "params"]),
        flips in prop::collection::vec(any::<bool>(), 8),
        value in prop::sample::select(vec![r#""debug_setHead""#, "1", "[]", r#""2.0""#]),
        at_end in any::<bool>(),
    ) {
        let variant: String = key.chars().zip(flips.iter().cycle()).map(|(c, &f)| if f { c.to_ascii_uppercase() } else { c }).collect();
        let field = format!(r#""{variant}":{value}"#);
        let s = if at_end { format!("{},{field}}}", &obj[..obj.len() - 1]) } else { format!("{{{field},{}", &obj[1..]) };
        prop_assert_eq!(parse_request(s.as_bytes(), SR), Err(Denied::Malformed), "{}", s);
    }

    #[test]
    fn parse_answers_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..400), max in 0usize..1000) {
        let single = ok("eth_getTransactionByHash", &format!(r#"["{}"]"#, h(1)));
        let batch = raw(&format!("[{},{}]", call_json("eth_chainId", "[]"), call_json("eth_getBlockByHash", &format!(r#"["{}",false]"#, h(2))))).unwrap();
        for r in [&single, &batch] {
            let _ = parse_answers(r, &bytes, 7, max);
            let _ = parse_answers(r, &bytes, 7, usize::MAX);
        }
        let _ = parse_tag_answer(&bytes, 7);
    }

    #[test]
    fn canonicalisation_keeps_meaning_and_is_idempotent(v in json_value_s()) {
        let c = canon(&v).map_err(|e| TestCaseError::fail(format!("{e:?}: {v}")))?;
        let want: serde_json::Value = serde_json::from_str(&v).unwrap();
        let got: serde_json::Value = serde_json::from_str(&c).unwrap();
        prop_assert_eq!(got, want);
        prop_assert_eq!(canon(&c).unwrap(), c.clone(), "idempotent");
        prop_assert!(!whitespace_outside_strings(&c), "{}", c);
    }

    #[test]
    fn batch_answers_come_back_in_request_order(n in 1usize..=MAX_BATCH, seed in any::<u64>(), first_id in any::<u64>()) {
        let calls: Vec<String> = (0..n).map(|i| call_json("eth_getBlockByNumber", &format!(r#"["0x{i:x}",false]"#))).collect();
        let r = raw(&format!("[{}]", calls.join(","))).unwrap();
        let mut order: Vec<usize> = (0..n).collect();
        // A seeded shuffle.
        let mut x = seed | 1;
        for i in (1..n).rev() {
            x ^= x << 13; x ^= x >> 7; x ^= x << 17;
            order.swap(i, (x % (i as u64 + 1)) as usize);
        }
        let body = format!("[{}]", order.iter().map(|&i| envelope(&first_id.wrapping_add(i as u64).to_string(), &format!(r#""result":{{"n":{i}}}"#))).collect::<Vec<_>>().join(","));
        let a = parse_answers(&r, body.as_bytes(), first_id, usize::MAX).unwrap();
        for (i, x) in a.iter().enumerate() {
            let want = format!(r#"{{"n":{i}}}"#);
            prop_assert_eq!(&x.canonical, want.as_bytes());
        }
        // The cap is exact on the rendered bytes.
        let len = render(&r, &a).len();
        prop_assert!(parse_answers(&r, body.as_bytes(), first_id, len).is_ok());
        prop_assert_eq!(parse_answers(&r, body.as_bytes(), first_id, len - 1), Err(ResponseError::TooLarge));
    }
}
