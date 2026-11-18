//! Strict action-only RFC 8785 parsing. Legacy serde_json parsing features stay intact.
use anyhow::{Context, Result, ensure};
use serde::{
    Deserialize, Deserializer,
    de::{self, MapAccess, Visitor},
};
use serde_json::{Value, value::RawValue};
use std::collections::BTreeMap;

// Capture raw tokens: serde_json's numeric visitor can already have rounded an
// overflowing integer before visit_f64. Never validate integers at that point.
struct Object(BTreeMap<String, Box<RawValue>>);
impl<'de> Deserialize<'de> for Object {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Members;
        impl<'de> Visitor<'de> for Members {
            type Value = Object;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("an object without duplicate names")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Object, A::Error> {
                let mut members = BTreeMap::new();
                while let Some((name, value)) = map.next_entry::<String, Box<RawValue>>()? {
                    if members.insert(name, value).is_some() {
                        return Err(de::Error::custom("duplicate JSON key"));
                    }
                }
                Ok(Object(members))
            }
        }
        d.deserialize_map(Members)
    }
}
fn parse(raw: &RawValue, depth: usize) -> Result<Value> {
    ensure!(depth < 128, "action JSON nesting limit exceeded");
    let token = raw.get();
    match token.as_bytes()[0] {
        b'{' => {
            let Object(members) = serde_json::from_str(token)?;
            let mut out = serde_json::Map::new();
            for (name, value) in members {
                out.insert(name, parse(&value, depth + 1)?);
            }
            Ok(Value::Object(out))
        }
        b'[' => {
            let members: Vec<Box<RawValue>> = serde_json::from_str(token)?;
            Ok(Value::Array(
                members
                    .iter()
                    .map(|v| parse(v, depth + 1))
                    .collect::<Result<_>>()?,
            ))
        }
        b'-' | b'0'..=b'9' => {
            ensure!(
                !token.contains(['.', 'e', 'E']),
                "floats are outside the action contract"
            );
            let integer = token
                .parse::<i64>()
                .context("integer outside JCS safe domain")?;
            ensure!(
                (-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&integer),
                "integer outside JCS safe domain"
            );
            Ok(Value::Number(integer.into()))
        }
        _ => serde_json::from_str(token).context("invalid action scalar"),
    }
}
fn write(value: &Value, out: &mut String) -> Result<()> {
    match value {
        Value::Object(map) => {
            let mut members: Vec<_> = map.iter().collect();
            members.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (index, (name, value)) in members.into_iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(name)?);
                out.push(':');
                write(value, out)?;
            }
            out.push('}');
        }
        Value::Array(values) => {
            out.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    out.push(',');
                }
                write(value, out)?;
            }
            out.push(']');
        }
        Value::Number(number) => {
            let integer = number
                .as_i64()
                .context("action number must be an integer")?;
            out.push_str(&integer.to_string());
        }
        _ => out.push_str(&serde_json::to_string(value)?),
    }
    Ok(())
}
pub fn canonical_json(raw: &str) -> Result<String> {
    let token: Box<RawValue> = serde_json::from_str(raw).context("invalid action JSON")?;
    let value = parse(&token, 0)?;
    let mut output = String::new();
    write(&value, &mut output)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn jcs_utf16_and_object_order_vectors() {
        assert_eq!(
            canonical_json("{\"\u{e000}\":1,\"😀\":2}").unwrap(),
            "{\"😀\":2,\"\u{e000}\":1}"
        );
        assert_eq!(
            canonical_json(r#"{"z":2,"a":1}"#).unwrap(),
            r#"{"a":1,"z":2}"#
        );
    }
    #[test]
    fn jcs_negative_zero_and_safe_integer_vectors() {
        assert_eq!(
            canonical_json("[0,-0,9007199254740991,-9007199254740991]").unwrap(),
            "[0,0,9007199254740991,-9007199254740991]"
        );
        for number in [
            "9007199254740992",
            "9007199254740993",
            "9007199254740994",
            "-9007199254740992",
        ] {
            assert_eq!(
                canonical_json(number).unwrap_err().to_string(),
                "integer outside JCS safe domain"
            );
        }
    }
    #[test]
    fn jcs_duplicate_key_vectors() {
        for input in [r#"{"a":1,"a":2}"#, r#"{"x":[{"a":1,"\u0061":2}]}"#] {
            assert!(
                canonical_json(input)
                    .unwrap_err()
                    .to_string()
                    .contains("duplicate JSON key")
            );
        }
    }
    #[test]
    fn jcs_lone_surrogate_vector() {
        let error = canonical_json(r#"{"x":"\ud800"}"#).unwrap_err();
        assert!(
            format!("{error:#}").contains("unexpected end of hex escape"),
            "{error:#}"
        );
    }
}
