//! Read labels once at each proxy route boundary, outside the admission sequence.
use axum::{
    http::{HeaderMap, HeaderValue},
    response::Response,
};
use tracelane_shared::labels::{Dropped, LabelCaps, Labels, RawLabels, bound_labels};

pub(crate) type BoundedLabels = (Labels, Dropped);

pub(crate) fn read(headers: &HeaderMap, caps: &LabelCaps) -> BoundedLabels {
    let mut invalid = Dropped::default();
    let mut read = |header: &str, field: &str| {
        headers
            .get(header)
            .and_then(|value| match std::str::from_utf8(value.as_bytes()) {
                Ok(value) => Some(value.to_owned()),
                Err(_) => {
                    *invalid.entry(field.to_owned()).or_default() += 1;
                    None
                }
            })
    };
    let raw = RawLabels {
        metadata_json: read("x-tracelane-metadata", "metadata_keys"),
        tags: read("x-tracelane-tags", "tags")
            .map(|s| s.split(',').map(str::to_owned).collect())
            .unwrap_or_default(),
        environment: read("x-tracelane-environment", "environment"),
        release: read("x-tracelane-release", "release"),
        service: read("x-tracelane-service", "service"),
        ..Default::default()
    };
    let (labels, mut dropped) = bound_labels(raw, caps);
    for (key, count) in invalid {
        *dropped.entry(key).or_default() += count;
    }
    (labels, dropped)
}

pub(crate) fn attach<R: crate::admission::Route>(
    admitted: &mut crate::admission::Admitted<R>,
    labels: &BoundedLabels,
) {
    admitted.identity.labels = labels.clone();
    admitted.dispatch_guard.record_labels(labels.clone());
}

pub(crate) fn response(mut response: Response, labels: &BoundedLabels) -> Response {
    if !labels.1.is_empty() {
        let warning = format!(
            "labels_capped {}",
            labels
                .1
                .iter()
                .map(|(key, n)| format!("{key}={n}"))
                .collect::<Vec<_>>()
                .join(" ")
        );
        // Keys are our fixed counter vocabulary; the warning never echoes caller text.
        if let Ok(warning) = HeaderValue::from_str(&warning) {
            response.headers_mut().append("tracelane-warning", warning);
        }
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn warning_preserves_existing_values_and_never_echoes_labels() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-tracelane-environment",
            HeaderValue::from_bytes(&[255]).unwrap(),
        );
        let labels = read(&headers, &LabelCaps::embedded());
        assert_eq!(labels.1["environment"], 1);
        let mut result = Response::default();
        result.headers_mut().insert(
            "tracelane-warning",
            HeaderValue::from_static("existing_warning"),
        );
        let result = response(result, &labels);
        let values: Vec<_> = result
            .headers()
            .get_all("tracelane-warning")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            values,
            vec!["existing_warning", "labels_capped environment=1"]
        );
    }
}
