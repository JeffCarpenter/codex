//! Integration tests for OpenRouter provider support.

use codex_core::CodexAuth;
use codex_core::ConversationManager;
use codex_core::WireApi;
use codex_core::built_in_model_providers;
use codex_core::create_openrouter_provider;
use codex_core::protocol::EventMsg;
use codex_core::protocol::InputItem;
use codex_core::protocol::Op;
use core_test_support::load_default_config_for_test;
use core_test_support::skip_if_no_network;
use core_test_support::wait_for_event;
use pretty_assertions::assert_eq;
use serde_json::json;
use tempfile::TempDir;
use wiremock::Mock;
use wiremock::MockServer;
use wiremock::ResponseTemplate;
use wiremock::matchers::header;
use wiremock::matchers::method;
use wiremock::matchers::path;

#[test]
fn openrouter_provider_configuration() {
    let provider = create_openrouter_provider();

    assert_eq!(provider.name, "OpenRouter");
    assert_eq!(
        provider.base_url,
        Some("https://openrouter.ai/api/v1".to_string())
    );
    assert_eq!(provider.env_key, Some("OPENROUTER_API_KEY".to_string()));
    assert_eq!(provider.wire_api, WireApi::Chat);
    assert!(!provider.requires_openai_auth);
}

#[test]
fn openrouter_is_available_in_built_in_providers() {
    let providers = built_in_model_providers();
    assert!(
        providers.contains_key("openrouter"),
        "OpenRouter should be available as a built-in provider"
    );

    let openrouter = &providers["openrouter"];
    assert_eq!(openrouter.name, "OpenRouter");
    assert_eq!(openrouter.wire_api, WireApi::Chat);
}

#[test]
fn openrouter_uses_chat_completions_api() {
    let provider = create_openrouter_provider();

    // Verify it uses Chat API, not Responses API
    assert_eq!(
        provider.wire_api,
        WireApi::Chat,
        "OpenRouter should use the Chat Completions API"
    );

    // Verify base URL is correct
    assert_eq!(
        provider.base_url,
        Some("https://openrouter.ai/api/v1".to_string()),
        "OpenRouter base URL should be https://openrouter.ai/api/v1"
    );
}

#[test]
fn openrouter_requires_api_key_from_env() {
    let provider = create_openrouter_provider();

    // Clean slate
    unsafe {
        std::env::remove_var("OPENROUTER_API_KEY");
    }

    // Should error without the key
    let result = provider.api_key();
    assert!(
        result.is_err(),
        "Should require OPENROUTER_API_KEY environment variable"
    );

    // Should succeed with the key
    unsafe {
        std::env::set_var("OPENROUTER_API_KEY", "sk-or-test-key");
    }
    let result = provider.api_key();
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some("sk-or-test-key".to_string()));

    // Clean up
    unsafe {
        std::env::remove_var("OPENROUTER_API_KEY");
    }
}

#[test]
fn openrouter_handles_empty_api_key() {
    let provider = create_openrouter_provider();

    // Empty string should be treated as missing
    unsafe {
        std::env::set_var("OPENROUTER_API_KEY", "");
    }
    let result = provider.api_key();
    assert!(
        result.is_err(),
        "Empty OPENROUTER_API_KEY should be treated as missing"
    );

    // Whitespace-only should also be treated as missing
    unsafe {
        std::env::set_var("OPENROUTER_API_KEY", "   ");
    }
    let result = provider.api_key();
    assert!(
        result.is_err(),
        "Whitespace-only OPENROUTER_API_KEY should be treated as missing"
    );

    // Clean up
    unsafe {
        std::env::remove_var("OPENROUTER_API_KEY");
    }
}

#[test]
fn openrouter_optional_headers_configuration() {
    let provider = create_openrouter_provider();

    let env_headers = provider
        .env_http_headers
        .as_ref()
        .expect("OpenRouter should have env_http_headers configured");

    assert_eq!(
        env_headers.get("HTTP-Referer"),
        Some(&"OPENROUTER_HTTP_REFERER".to_string()),
        "Should support HTTP-Referer header via env var"
    );
    assert_eq!(
        env_headers.get("X-Title"),
        Some(&"OPENROUTER_APP_TITLE".to_string()),
        "Should support X-Title header via env var"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openrouter_sends_correct_request_format() {
    skip_if_no_network!();

    let server = MockServer::start().await;

    // Mock a successful chat completion response
    let mock_response = json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "openai/gpt-4",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Hello from OpenRouter!"
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 10,
            "completion_tokens": 5,
            "total_tokens": 15
        }
    });

    let response = ResponseTemplate::new(200)
        .insert_header("content-type", "application/json")
        .set_body_json(&mock_response);

    let mock = Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer test-openrouter-key"))
        .respond_with(response)
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    // Configure Codex with OpenRouter provider pointing to mock server
    let mut provider = create_openrouter_provider();
    provider.base_url = Some(format!("{}/v1", server.uri()));

    let codex_home = TempDir::new().unwrap();
    let mut config = load_default_config_for_test(&codex_home);
    config.model = "gpt-4".to_string();
    config.model_provider = provider;

    // Set the API key
    unsafe {
        std::env::set_var("OPENROUTER_API_KEY", "test-openrouter-key");
    }

    let conversation_manager =
        ConversationManager::with_auth(CodexAuth::from_api_key("test-openrouter-key"));
    let codex = conversation_manager
        .new_conversation(config)
        .await
        .expect("create conversation")
        .conversation;

    codex
        .submit(Op::UserInput {
            items: vec![InputItem::Text {
                text: "Hello".into(),
            }],
        })
        .await
        .expect("submit user input");

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    // Verify the mock was called
    drop(mock);

    // Clean up
    unsafe {
        std::env::remove_var("OPENROUTER_API_KEY");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openrouter_includes_optional_headers_when_set() {
    skip_if_no_network!();

    let server = MockServer::start().await;

    let mock_response = json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "openai/gpt-4",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Response"
            },
            "finish_reason": "stop"
        }]
    });

    let response = ResponseTemplate::new(200)
        .insert_header("content-type", "application/json")
        .set_body_json(&mock_response);

    let mock = Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("HTTP-Referer", "https://myapp.example.com"))
        .and(header("X-Title", "My Codex App"))
        .respond_with(response)
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    // Set optional headers
    unsafe {
        std::env::set_var("OPENROUTER_HTTP_REFERER", "https://myapp.example.com");
        std::env::set_var("OPENROUTER_APP_TITLE", "My Codex App");
        std::env::set_var("OPENROUTER_API_KEY", "test-key");
    }

    let mut provider = create_openrouter_provider();
    provider.base_url = Some(format!("{}/v1", server.uri()));

    let codex_home = TempDir::new().unwrap();
    let mut config = load_default_config_for_test(&codex_home);
    config.model = "gpt-4".to_string();
    config.model_provider = provider;

    let conversation_manager = ConversationManager::with_auth(CodexAuth::from_api_key("test-key"));
    let codex = conversation_manager
        .new_conversation(config)
        .await
        .expect("create conversation")
        .conversation;

    codex
        .submit(Op::UserInput {
            items: vec![InputItem::Text {
                text: "Test".into(),
            }],
        })
        .await
        .expect("submit user input");

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    drop(mock);

    // Clean up
    unsafe {
        std::env::remove_var("OPENROUTER_HTTP_REFERER");
        std::env::remove_var("OPENROUTER_APP_TITLE");
        std::env::remove_var("OPENROUTER_API_KEY");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn openrouter_works_without_optional_headers() {
    skip_if_no_network!();

    let server = MockServer::start().await;

    let mock_response = json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1234567890,
        "model": "openai/gpt-4",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "Response"
            },
            "finish_reason": "stop"
        }]
    });

    let response = ResponseTemplate::new(200)
        .insert_header("content-type", "application/json")
        .set_body_json(&mock_response);

    // Mock should succeed even without optional headers
    let mock = Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(response)
        .expect(1)
        .mount_as_scoped(&server)
        .await;

    // Ensure optional headers are NOT set
    unsafe {
        std::env::remove_var("OPENROUTER_HTTP_REFERER");
        std::env::remove_var("OPENROUTER_APP_TITLE");
        std::env::set_var("OPENROUTER_API_KEY", "test-key");
    }

    let mut provider = create_openrouter_provider();
    provider.base_url = Some(format!("{}/v1", server.uri()));

    let codex_home = TempDir::new().unwrap();
    let mut config = load_default_config_for_test(&codex_home);
    config.model = "gpt-4".to_string();
    config.model_provider = provider;

    let conversation_manager = ConversationManager::with_auth(CodexAuth::from_api_key("test-key"));
    let codex = conversation_manager
        .new_conversation(config)
        .await
        .expect("create conversation")
        .conversation;

    codex
        .submit(Op::UserInput {
            items: vec![InputItem::Text {
                text: "Test".into(),
            }],
        })
        .await
        .expect("submit user input");

    wait_for_event(&codex, |ev| matches!(ev, EventMsg::TaskComplete(_))).await;

    drop(mock);

    // Clean up
    unsafe {
        std::env::remove_var("OPENROUTER_API_KEY");
    }
}

#[test]
fn openrouter_provider_uses_chat_not_responses_api() {
    let provider = create_openrouter_provider();

    assert_eq!(
        provider.wire_api,
        WireApi::Chat,
        "OpenRouter should use Chat Completions API, not Responses API"
    );

    // Verify base URL doesn't contain /responses
    let base_url = provider.base_url.as_ref().unwrap();
    assert!(
        !base_url.contains("/responses"),
        "Base URL should not contain /responses, got: {base_url}"
    );
    assert!(
        base_url.contains("/api/v1"),
        "Base URL should contain /api/v1, got: {base_url}"
    );
}

#[test]
fn openrouter_does_not_require_openai_auth() {
    let provider = create_openrouter_provider();

    assert!(
        !provider.requires_openai_auth,
        "OpenRouter should not require OpenAI authentication"
    );
}

#[test]
fn openrouter_retry_and_timeout_defaults() {
    let provider = create_openrouter_provider();

    // Should use global defaults
    assert!(provider.request_max_retries.is_none());
    assert!(provider.stream_max_retries.is_none());
    assert!(provider.stream_idle_timeout_ms.is_none());

    // Verify the effective values use defaults
    assert!(provider.request_max_retries() > 0);
    assert!(provider.stream_max_retries() > 0);
    assert!(provider.stream_idle_timeout().as_secs() > 0);
}
