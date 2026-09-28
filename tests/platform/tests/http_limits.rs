//! Hostile HTTP bodies must be rejected before the complete stream is collected.
use pairkey_coordinator::{Config, Relay};
use pairkey_sdk::http::{bounded_body, MAX_SERVICE_RESPONSE};
use std::{
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn server(declared_length: bool) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = stream.read(&mut buffer).unwrap();
            if n == 0 {
                return;
            }
            request.extend_from_slice(&buffer[..n]);
            assert!(request.len() < 16_384);
        }
        if declared_length {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n").unwrap();
            // Keep the body unavailable: a whole-body read would time out.
            thread::sleep(Duration::from_millis(200));
        } else {
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").unwrap();
            let chunk = vec![b' '; 4096];
            for _ in 0..16 {
                if stream
                    .write_all(b"1000\r\n")
                    .and_then(|_| stream.write_all(&chunk))
                    .and_then(|_| stream.write_all(b"\r\n"))
                    .is_err()
                {
                    return;
                }
            }
            // Deliberately never send the terminating chunk. The limit must fire first.
            thread::sleep(Duration::from_millis(200));
        }
    });
    (endpoint, handle)
}

#[tokio::test]
async fn content_length_and_unfinished_chunked_stream_are_bounded() {
    for declared in [true, false] {
        let (url, handle) = server(declared);
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let response = client.get(url).send().await.unwrap();
        let error = bounded_body(response, MAX_SERVICE_RESPONSE)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "HTTP response exceeds limit");
        handle.join().unwrap();
    }
}

#[tokio::test]
async fn relay_health_and_sdk_poll_use_the_streaming_limit() {
    let (url, handle) = server(false);
    let relay = Relay::new(Config {
        bind: "127.0.0.1:0".into(),
        workers: [url, "http://127.0.0.1:1".into()],
        identities: [[1; 32], [2; 32]],
    })
    .unwrap();
    assert_eq!(
        relay
            .health(0)
            .await
            .err()
            .expect("oversized response accepted")
            .to_string(),
        "HTTP response exceeds limit"
    );
    handle.join().unwrap();
    let (url, handle) = server(false);
    let client = pairkey_sdk::service::Client::new(url).unwrap();
    let id = solana_sdk::pubkey::Pubkey::new_from_array([9; 32]).to_string();
    assert_eq!(
        client.poll(&id).await.unwrap_err().to_string(),
        "HTTP response exceeds limit"
    );
    handle.join().unwrap();
}

#[tokio::test]
async fn exact_limit_is_accepted_and_transport_errors_omit_url_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 2048];
        let _ = stream.read(&mut request);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n1234")
            .unwrap();
    });
    let response = reqwest::get(format!("http://{address}")).await.unwrap();
    assert_eq!(bounded_body(response, 4).await.unwrap(), b"1234");
    server.join().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let rpc = pairkey_sdk::rpc::Rpc::new(format!(
        "http://example-user:example-secret@{address}/?token=example-token"
    ))
    .unwrap();
    let error = rpc
        .call("getGenesisHash", serde_json::json!([]))
        .await
        .unwrap_err()
        .to_string();
    assert!(
        !error.contains("example-secret")
            && !error.contains("example-token")
            && !error.contains("example-user")
    );
}
