use gotcha_server::{
    HTTP_CLIENT,
    encodings::{Base64, UrlSafe},
    routes::challenge::{
        AccessibilityRequest, ChallengeResponse, ChallengeResults, GetChallenge, PowResponse,
        PreAnalysisRequest, PreAnalysisResponse, ProofOfWork,
    },
    tokens::{
        TimeClaims, pow_challenge,
        response::{JWT_RESPONSE_ALGORITHM, ResponseClaims},
    },
};
use gotcha_server_macros::integration_test;
use jsonwebtoken::{DecodingKey, Validation};
use reqwest::StatusCode;
use url::Url;

async fn get_pow_helper(port: u16, site_key: &Base64<UrlSafe>) -> anyhow::Result<PowResponse> {
    Ok(HTTP_CLIENT
        .get(format!(
            "http://localhost:{port}/api/challenge/proof-of-work"
        ))
        .header("X-Site-Key", site_key.as_str())
        .send()
        .await?
        .json::<PowResponse>()
        .await?)
}

#[ignore = "TODO: insert challenge and then request"]
#[integration_test]
async fn get_challenge(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();

    let response = HTTP_CLIENT
        .get(format!("http://localhost:{port}/api/challenge"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let _challenge: GetChallenge = response.json().await?;

    Ok(())
}

#[ignore = "TODO: create one db per test to isolate"]
#[integration_test]
async fn get_challenge_fails(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();

    let response = HTTP_CLIENT
        .get(format!("http://localhost:{port}/api/challenge"))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

// This test overtime gets more meaningless and untestable
#[integration_test]
async fn process_successful_challenge(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let response = HTTP_CLIENT
        .post(format!("http://localhost:{port}/api/challenge/process"))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&ChallengeResults {
            success: true,
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            challenge: Url::parse("https://gotcha-integration.test.com/im-not-a-robot/index.html")?,
            interactions: vec![],
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let ChallengeResponse { token } = response.json().await?;
    eprintln!("{token}");
    let token_data = jsonwebtoken::decode::<TimeClaims<ResponseClaims>>(
        &token,
        &DecodingKey::from_base64_secret(enc_key.as_str())?,
        &Validation::new(JWT_RESPONSE_ALGORITHM),
    )?;
    assert_eq!(token_data.header.alg, JWT_RESPONSE_ALGORITHM);
    // assert!(token_data.claims.custom.score >= 0.5);

    Ok(())
}

#[integration_test]
async fn process_failed_challenge(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let response = HTTP_CLIENT
        .post(format!("http://localhost:{port}/api/challenge/process"))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&ChallengeResults {
            success: false,
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            challenge: Url::parse("https://gotcha-integration.test.com/im-not-a-robot/index.html")?,
            interactions: vec![],
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let ChallengeResponse { token } = response.json().await?;
    eprintln!("{token}");
    let token_data = jsonwebtoken::decode::<TimeClaims<ResponseClaims>>(
        &token,
        &DecodingKey::from_base64_secret(enc_key.as_str())?,
        &Validation::new(JWT_RESPONSE_ALGORITHM),
    )?;
    assert_eq!(token_data.header.alg, JWT_RESPONSE_ALGORITHM);
    assert!(token_data.claims.other.score == 0.);

    Ok(())
}

#[integration_test]
async fn process_challenge_with_invalid_secret(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();

    let response = HTTP_CLIENT
        .post(format!("http://localhost:{port}/api/challenge/process"))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", "bXktd3Jvbmctc2VjcmV0")
        .json(&serde_json::json!({
            "success": false,
            // "site_key": "bXktd3Jvbmctc2VjcmV0", // `my-wrong-secret` in base64
            "hostname": "website-integration.test.com",
            "challenge": "https://gotcha-integration.test.com/im-not-a-robot/index.html",
            "interactions": [],
        }))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[integration_test]
async fn process_challenge_wrong_hostname(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let response = HTTP_CLIENT
        .post(format!("http://localhost:{port}/api/challenge/process"))
        .header("Origin", "http://wrong-website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&ChallengeResults {
            success: true,
            // site_key,
            hostname: "wrong-website-integration.test.com".parse()?,
            challenge: Url::parse("https://gotcha-integration.test.com/im-not-a-robot/index.html")?,
            interactions: vec![],
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[integration_test]
async fn process_pre_analysis_succeeds_but_with_failure(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let pow_res: PowResponse = get_pow_helper(port, &site_key).await?;
    let pow_challenge = pow_challenge::decode(&pow_res.token, enc_key.as_str())
        .expect("server returned invalid PoW");

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-pre-analysis"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&PreAnalysisRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            interactions: vec![],
            proof_of_work: ProofOfWork {
                challenge: pow_res.token,
                solution: pow_challenge.solve(),
            },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response: PreAnalysisResponse = response.json().await?;
    assert_eq!(response, PreAnalysisResponse::Failure);

    Ok(())
}

#[integration_test]
async fn process_pre_analysis_fails_on_invalid_proof_of_work(
    server: TestContext,
) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-pre-analysis"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&PreAnalysisRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            interactions: vec![],
            proof_of_work: ProofOfWork { challenge: "".into(), solution: 0 },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[integration_test]
async fn process_pre_analysis_fails_on_proof_of_work_failed(
    server: TestContext,
) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let pow: PowResponse = get_pow_helper(port, &site_key).await?;

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-pre-analysis"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&PreAnalysisRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            interactions: vec![],
            proof_of_work: ProofOfWork { challenge: pow.token, solution: 0 },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[integration_test]
async fn process_pre_analysis_with_wrong_hostname(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let pow_res: PowResponse = get_pow_helper(port, &site_key).await?;
    let pow_challenge = pow_challenge::decode(&pow_res.token, enc_key.as_str())
        .expect("server returned invalid PoW");

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-pre-analysis"
        ))
        .header("Origin", "http://wrong-website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&PreAnalysisRequest {
            // site_key,
            hostname: "wrong-website-integration.test.com".parse()?,
            interactions: vec![],
            proof_of_work: ProofOfWork {
                challenge: pow_res.token,
                solution: pow_challenge.solve(),
            },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[integration_test]
async fn process_accessibility_success(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let pow_res: PowResponse = get_pow_helper(port, &site_key).await?;
    let pow_challenge = pow_challenge::decode(&pow_res.token, enc_key.as_str())
        .expect("server returned invalid PoW");

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-accessibility"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&AccessibilityRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            proof_of_work: ProofOfWork {
                challenge: pow_res.token,
                solution: pow_challenge.solve(),
            },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response: PreAnalysisResponse = response.json().await?;
    assert!(matches!(response, PreAnalysisResponse::Success { .. }));

    Ok(())
}

#[integration_test]
async fn process_accessibility_fails_on_invalid_proof_of_work(
    server: TestContext,
) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-accessibility"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&AccessibilityRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            proof_of_work: ProofOfWork { challenge: "".into(), solution: 0 },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[integration_test]
async fn process_accessibility_fails_on_proof_of_work_failed(
    server: TestContext,
) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let pow: PowResponse = get_pow_helper(port, &site_key).await?;

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-accessibility"
        ))
        .header("Origin", "http://website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&AccessibilityRequest {
            // site_key,
            hostname: "website-integration.test.com".parse()?,
            proof_of_work: ProofOfWork { challenge: pow.token, solution: 0 },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}

#[integration_test]
async fn process_accessibility_with_wrong_hostname(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;
    let enc_key = server.db_enconding_key().await;

    let pow_res: PowResponse = get_pow_helper(port, &site_key).await?;
    let pow_challenge = pow_challenge::decode(&pow_res.token, enc_key.as_str())
        .expect("server returned invalid PoW");

    let response = HTTP_CLIENT
        .post(format!(
            "http://localhost:{port}/api/challenge/process-accessibility"
        ))
        .header("Origin", "http://wrong-website-integration.test.com")
        .header("X-Site-Key", site_key.as_str())
        .json(&AccessibilityRequest {
            // site_key,
            hostname: "wrong-website-integration.test.com".parse()?,
            proof_of_work: ProofOfWork {
                challenge: pow_res.token,
                solution: pow_challenge.solve(),
            },
        })
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    Ok(())
}

#[integration_test]
async fn get_proof_of_work_challenge(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();
    let site_key = server.db_api_site_key().await;

    let response = HTTP_CLIENT
        .get(format!(
            "http://localhost:{port}/api/challenge/proof-of-work"
        ))
        .header("X-Site-Key", site_key.as_str())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

    let response: PowResponse = response.json().await?;
    assert!(!response.token.is_empty());

    Ok(())
}

#[integration_test]
async fn get_proof_of_work_challenge_no_site_key(server: TestContext) -> anyhow::Result<()> {
    let port = server.port();

    let response = HTTP_CLIENT
        .get(format!(
            "http://localhost:{port}/api/challenge/proof-of-work"
        ))
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    Ok(())
}
