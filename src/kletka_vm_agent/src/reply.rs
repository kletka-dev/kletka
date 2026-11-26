use axum::Json;
use axum::body::{Body, Bytes};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn json_error(status: StatusCode, message: impl std::fmt::Display) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": message.to_string() })),
    )
        .into_response()
}

pub fn json_ok(body: serde_json::Value) -> Response {
    (StatusCode::OK, Json(body)).into_response()
}

pub fn reader_body<R>(reader: R, chunk: usize) -> Body
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let stream = futures_util::stream::unfold(
        (reader, vec![0u8; chunk]),
        |(mut reader, mut buf)| async move {
            match reader.read(&mut buf).await {
                Ok(0) => None,
                Ok(n) => Some((
                    Ok::<_, std::io::Error>(Bytes::copy_from_slice(&buf[..n])),
                    (reader, buf),
                )),
                Err(err) => Some((Err(err), (reader, buf))),
            }
        },
    );
    Body::from_stream(stream)
}
