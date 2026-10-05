use anyhow::Result;
use lettre::{
    message::header::ContentType,
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use tracing::{error, info};

pub async fn send_otp_email(to_email: &str, otp: &str, context: &str) -> Result<()> {
    let is_reset = context == "reset";
    let subject  = if is_reset { "Reset Your Chet Password" } else { "Your Chet Verification Code" };
    let title    = if is_reset { "Password Reset Request" } else { "Welcome to Chet!" };
    let body_text = if is_reset { "You requested a password reset." } else { "We are excited to have you on board." };

    let html = format!(
        r#"<h3>{title}</h3><p>{body_text}</p><p>Your verification code is: <b style="font-size:24px;color:#7c6cff">{otp}</b></p><p>This code expires in 10 minutes.</p>"#
    );

    let smtp_user = std::env::var("SMTP_USER").unwrap_or_else(|_| "rakibkumar151@gmail.com".into());
    let smtp_pass = std::env::var("SMTP_PASS").unwrap_or_else(|_| "ziasmvxfmtaxrxbx".into());

    let email = Message::builder()
        .from(format!("Chet <{}>", smtp_user).parse()?)
        .to(to_email.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_HTML)
        .body(html)?;

    // Try proxy tunnel first (Render SMTP block bypass)
    let proxy_host = std::env::var("PROXY_HOST").unwrap_or_else(|_| "change4.owlproxy.com".into());
    let proxy_port: u16 = std::env::var("PROXY_PORT").unwrap_or_else(|_| "7778".into())
        .parse().unwrap_or(7778);
    let proxy_user = std::env::var("PROXY_USER")
        .unwrap_or_else(|_| "izUU8KQkEm50_custom_zone_IN_st__city_sid_26821469_time_5".into());
    let proxy_pass_val = std::env::var("PROXY_PASS").unwrap_or_else(|_| "5559057".into());

    // Try SMTP via proxy tunnel
    match send_via_proxy(&email, &smtp_user, &smtp_pass, &proxy_host, proxy_port, &proxy_user, &proxy_pass_val).await {
        Ok(_) => {
            info!("[SMTP] Email sent via proxy to {}", to_email);
            return Ok(());
        }
        Err(e) => {
            error!("[SMTP-PROXY] Proxy send failed, trying direct SMTP: {}", e);
        }
    }

    // Fallback: direct Gmail SMTP
    let creds = Credentials::new(smtp_user.clone(), smtp_pass.clone());
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(email).await?;
    info!("[SMTP] Email sent direct to {}", to_email);
    Ok(())
}

async fn send_via_proxy(
    email: &Message,
    smtp_user: &str,
    smtp_pass: &str,
    proxy_host: &str,
    proxy_port: u16,
    proxy_user: &str,
    proxy_pass_val: &str,
) -> Result<()> {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    // Connect to proxy
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        TcpStream::connect((proxy_host, proxy_port))
    ).await??;

    // Send HTTP CONNECT
    let auth = STANDARD.encode(format!("{}:{}", proxy_user, proxy_pass_val));
    let connect_req = format!(
        "CONNECT smtp.gmail.com:587 HTTP/1.1\r\nHost: smtp.gmail.com:587\r\nProxy-Authorization: Basic {}\r\nConnection: keep-alive\r\n\r\n",
        auth
    );
    stream.write_all(connect_req.as_bytes()).await?;

    // Read response
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        stream.read(&mut buf)
    ).await??;
    let resp = String::from_utf8_lossy(&buf[..n]);
    anyhow::ensure!(resp.contains("200"), "Proxy CONNECT failed: {}", resp.split('\n').next().unwrap_or(""));

    // Now tunnel SMTP over the established connection.
    // lettre requires a direct address, so we bind a local listener and pipe through.
    let local_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local_port = local_listener.local_addr()?.port();

    tokio::spawn(async move {
        if let Ok((mut local_client, _)) = local_listener.accept().await {
            let _ = tokio::io::copy_bidirectional(&mut local_client, &mut stream).await;
        }
    });

    let creds = Credentials::new(smtp_user.to_string(), smtp_pass.to_string());
    let mailer = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&format!("127.0.0.1:{}", local_port))
        .port(local_port)
        .credentials(creds)
        .build();

    mailer.send(email.clone()).await?;
    Ok(())
}

/// Verify captcha via external service
pub async fn verify_captcha(client: &reqwest::Client, id: &str, answer: &str) -> bool {
    if id.is_empty() || answer.is_empty() { return false; }
    let res = client
        .post("https://captcha-generator-v1.onrender.com/api/captcha/verify")
        .json(&serde_json::json!({ "id": id, "answer": answer }))
        .send()
        .await;
    match res {
        Ok(r) => r.json::<serde_json::Value>().await.map(|v| v["success"] == true).unwrap_or(false),
        Err(_) => false,
    }
}
