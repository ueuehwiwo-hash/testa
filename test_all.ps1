$BASE = "http://localhost:3777"
$script:PASS = 0
$script:FAIL = 0
$script:SKIP = 0

function Test-Pass($msg)  { Write-Host "  [PASS] $msg" -ForegroundColor Green;  $script:PASS++ }
function Test-Fail($msg)  { Write-Host "  [FAIL] $msg" -ForegroundColor Red;    $script:FAIL++ }
function Test-Skip($msg)  { Write-Host "  [SKIP] $msg" -ForegroundColor Yellow; $script:SKIP++ }
function Test-Section($n) { Write-Host "`n=== $n ===" -ForegroundColor Cyan }

function Invoke-API($method, $path, $data = $null, $token = $null) {
    $h = @{ "Content-Type" = "application/json" }
    if ($token) { $h["Authorization"] = "Bearer $token" }
    $uri = "$BASE$path"
    try {
        $params = @{ Uri = $uri; Headers = $h; UseBasicParsing = $true; ErrorAction = "Stop" }
        if ($method -eq "POST") {
            $params["Method"] = "POST"
            $params["Body"]   = ($data | ConvertTo-Json -Depth 5)
        }
        $r = Invoke-WebRequest @params
        $body = $null
        try { $body = $r.Content | ConvertFrom-Json } catch {}
        return @{ status = [int]$r.StatusCode; body = $body; raw = $r.Content }
    } catch {
        $code = 0
        try { $code = [int]$_.Exception.Response.StatusCode.value__ } catch {}
        $raw  = ""
        $body = $null
        try {
            $stream = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($stream)
            $raw    = $reader.ReadToEnd()
            $body   = $raw | ConvertFrom-Json -ErrorAction SilentlyContinue
        } catch {}
        return @{ status = $code; body = $body; raw = $raw }
    }
}

function GET($path, $token = $null)       { Invoke-API "GET"  $path $null $token }
function POST($path, $data, $token = $null) { Invoke-API "POST" $path $data $token }

Write-Host ""
Write-Host "Randerx Rust -- Full Logic Test Suite" -ForegroundColor Magenta
Write-Host "Target: $BASE" -ForegroundColor Gray

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "1. Health and Root"

$r = GET "/api/health"
if ($r.status -eq 200 -and $r.body.ok -eq $true) { Test-Pass "GET /api/health -> 200 ok=true" }
else { Test-Fail "GET /api/health -> $($r.status) raw=$($r.raw)" }

$r = GET "/"
if ($r.status -eq 200 -and $r.body.name) { Test-Pass "GET / -> 200 name=$($r.body.name)" }
else { Test-Fail "GET / -> $($r.status)" }

$r = GET "/google27d380bdf3dc690b.html"
if ($r.status -eq 200) { Test-Pass "GET /google27d380bdf3dc690b.html -> 200" }
else { Test-Fail "GET /google-verify -> $($r.status)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "2. TURN Credentials"

$r = GET "/api/turn-credentials"
if ($r.status -eq 200 -and $r.body.username -and $r.body.credential -and $r.body.urls) {
    Test-Pass "GET /api/turn-credentials -> 200"
    $parts = $r.body.username.Split(":")
    if ($parts.Count -eq 2 -and ($parts[0] -as [long]) -gt 1000000) {
        Test-Pass "  username format: $($r.body.username)"
    } else { Test-Fail "  bad username format: $($r.body.username)" }
    if ($r.body.credential.Length -gt 10) { Test-Pass "  credential set len=$($r.body.credential.Length)" }
    else { Test-Fail "  credential too short" }
    if (($r.body.urls | Where-Object { $_ -match "udp"  }).Count -gt 0) { Test-Pass "  UDP URL present" } else { Test-Fail "  UDP missing" }
    if (($r.body.urls | Where-Object { $_ -match "tcp"  }).Count -gt 0) { Test-Pass "  TCP URL present" } else { Test-Fail "  TCP missing" }
    if (($r.body.urls | Where-Object { $_ -match "turns:" }).Count -gt 0) { Test-Pass "  TURNS URL present" } else { Test-Fail "  TURNS missing" }
} else { Test-Fail "GET /api/turn-credentials -> $($r.status) raw=$($r.raw)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "3. Auth Register -- Input Validation"

# Short password
$r = POST "/api/auth/register" @{ username="gooduser"; first_name="T"; last_name="U"; email="t@gmail.com"; password="12345"; captcha_id="x"; captcha_answer="x" }
if ($r.status -eq 400) {
    $errText = if ($r.body) { $r.body.error } else { $r.raw }
    if ("$errText" -match "6|Password|password") { Test-Pass "Short password -> 400 err=$errText" }
    else { Test-Fail "Short password -> 400 but wrong error: $errText" }
} else { Test-Fail "Short password -> $($r.status) expected 400" }

# Username too short
$r = POST "/api/auth/register" @{ username="ab"; first_name="T"; last_name="U"; email="t@gmail.com"; password="password123"; captcha_id="x"; captcha_answer="x" }
if ($r.status -eq 400) {
    $errText = if ($r.body) { $r.body.error } else { $r.raw }
    if ("$errText" -match "[Uu]sername") { Test-Pass "Short username -> 400 err=$errText" }
    else { Test-Fail "Short username -> 400 but wrong error: $errText" }
} else { Test-Fail "Short username -> $($r.status) expected 400" }

# Username with dash (invalid char)
$r = POST "/api/auth/register" @{ username="bad-username"; first_name="T"; last_name="U"; email="t@gmail.com"; password="password123"; captcha_id="x"; captcha_answer="x" }
if ($r.status -eq 400) {
    $errText = if ($r.body) { $r.body.error } else { $r.raw }
    if ("$errText" -match "[Uu]sername") { Test-Pass "Username with dash -> 400 err=$errText" }
    else { Test-Fail "Username with dash -> 400 but wrong error: $errText" }
} else { Test-Fail "Username with dash -> $($r.status) expected 400" }

# Bad CAPTCHA
$r = POST "/api/auth/register" @{ username="gooduser3"; first_name="T"; last_name="U"; email="t@gmail.com"; password="password123"; captcha_id="invalid123"; captcha_answer="wronganswer" }
if ($r.status -eq 400) {
    $errText = if ($r.body) { $r.body.error } else { $r.raw }
    if ("$errText" -match "[Cc]aptcha|CAPTCHA") { Test-Pass "Bad CAPTCHA -> 400 err=$errText" }
    else { Test-Fail "Bad CAPTCHA -> 400 wrong error: $errText" }
} else { Test-Fail "Bad CAPTCHA -> $($r.status) expected 400" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "4. Auth Login -- Validation"

$r = POST "/api/auth/login" @{ identifier=""; password="" }
if ($r.status -eq 400) { Test-Pass "Empty login -> 400" }
else { Test-Fail "Empty login -> $($r.status)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "5. JWT Middleware -- All Protected Routes"

$protectedGET = @(
    "/api/auth/me",
    "/api/users",
    "/api/users/testuid123",
    "/api/messages/testuid123"
)
foreach ($route in $protectedGET) {
    $r = GET $route
    if ($r.status -eq 401) { Test-Pass "GET $route (no token) -> 401" }
    else { Test-Fail "GET $route (no token) -> $($r.status) expected 401" }

    $r = GET $route "garbage.token.value"
    if ($r.status -eq 401) { Test-Pass "GET $route (bad token) -> 401" }
    else { Test-Fail "GET $route (bad token) -> $($r.status)" }
}

$r = POST "/api/messages" @{ to_uid="UIDTEST"; text="hi" }
if ($r.status -eq 401) { Test-Pass "POST /api/messages (no token) -> 401" }
else { Test-Fail "POST /api/messages (no token) -> $($r.status)" }

$r = POST "/api/calls/initiate" @{ target_uid="UIDTEST" }
if ($r.status -eq 401) { Test-Pass "POST /api/calls/initiate (no token) -> 401" }
else { Test-Fail "POST /api/calls/initiate (no token) -> $($r.status)" }

$r = POST "/api/users/verify" @{ uid="UIDTEST"; is_verified=$true }
if ($r.status -eq 401) { Test-Pass "POST /api/users/verify (no token) -> 401" }
else { Test-Fail "POST /api/users/verify (no token) -> $($r.status)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "6. Password Reset Flow"

$r = POST "/api/auth/forgot-password" @{ email="nonexistent@example.com" }
if ($r.status -eq 200 -and $r.body.success -eq $true) { Test-Pass "Forgot password (no info leak) -> 200 success=true" }
else { Test-Fail "Forgot password -> $($r.status) raw=$($r.raw)" }

$r = POST "/api/auth/reset-password" @{ reset_token="anytoken"; newPassword="short" }
if ($r.status -eq 400) { Test-Pass "Reset pw (short pw) -> 400 validated first" }
else { Test-Fail "Reset pw short pw -> $($r.status)" }

$r = POST "/api/auth/reset-password" @{ reset_token="bad.invalid.jwt.token.here"; newPassword="validpassword123" }
if ($r.status -eq 401) { Test-Pass "Reset pw (bad token) -> 401" }
else { Test-Fail "Reset pw bad token -> $($r.status)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "7. Captcha Proxy"

$r = GET "/api/captcha/init"
if ($r.status -eq 200 -and $r.body.id -and $r.body.image_url) {
    Test-Pass "GET /api/captcha/init -> 200 id=$($r.body.id)"
    if ($r.body.image_url -match "/api/captcha/render/") { Test-Pass "  image_url points to local proxy" }
    else { Test-Fail "  bad image_url: $($r.body.image_url)" }
    $r2 = GET "/api/captcha/render/$($r.body.id)"
    if ($r2.status -eq 200) { Test-Pass "GET /api/captcha/render/:id -> 200" }
    else { Test-Fail "GET /api/captcha/render/:id -> $($r2.status)" }
} else { Test-Skip "Captcha init -> $($r.status) (upstream may be cold)" }

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "8. DB Connectivity (real Turso URL required)"

$r = GET "/api/db-test"
if ($r.status -eq 200 -and $r.body.ok -eq $true) {
    Test-Pass "GET /api/db-test -> 200 CONNECTED"
} elseif ($r.status -eq 200 -and $r.body.ok -eq $false) {
    Test-Skip "GET /api/db-test -> DB offline: $($r.body.error)"
} else {
    Test-Fail "GET /api/db-test -> $($r.status)"
}

# ─────────────────────────────────────────────────────────────────────────────
Test-Section "9. DB Schema Endpoint"

$r = GET "/api/db-schema"
if ($r.status -eq 200) {
    Test-Pass "GET /api/db-schema -> 200"
} elseif ($r.status -in 200, 500) {
    Test-Skip "GET /api/db-schema -> $($r.status) (DB offline expected)"
} else { Test-Fail "GET /api/db-schema -> $($r.status)" }

# ─────────────────────────────────────────────────────────────────────────────
$total = $script:PASS + $script:FAIL + $script:SKIP
Write-Host ""
Write-Host ("=" * 50) -ForegroundColor White
Write-Host "Total: $total   PASS: $($script:PASS)   FAIL: $($script:FAIL)   SKIP: $($script:SKIP)"
if ($script:FAIL -eq 0) {
    Write-Host "ALL TESTS PASSED" -ForegroundColor Green
} else {
    Write-Host "$($script:FAIL) test(s) FAILED" -ForegroundColor Red
    exit 1
}
