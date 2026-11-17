//! The example of the SDK guide is compiled into the crate and run verbatim.

#[path = "../../../../../../docs/guide/sdk-example.rs"]
mod example;

#[tokio::test]
async fn the_guide_example_round_trips_one_exchange() {
    let reply = tokio::time::timeout(std::time::Duration::from_secs(30), example::echo())
        .await
        .expect("the example finishes")
        .expect("the example succeeds");
    assert!(reply.starts_with("hello "), "{reply}");
    assert!(reply.ends_with(": ping"), "{reply}");
    // `hello <64 hex of the client key>: ping`
    let key = reply
        .strip_prefix("hello ")
        .and_then(|rest| rest.strip_suffix(": ping"))
        .expect("the reply has the documented shape");
    assert_eq!(key.len(), 64);
    assert!(key.parse::<crate::startup::facade::PeerKey>().is_ok());
}
