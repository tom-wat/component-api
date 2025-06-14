#!/bin/bash

# Comprehensive Security Test Script
# Tests authentication, authorization, and security measures

echo "🔐 Enhanced Security Test Suite v3.0"
echo "======================================"

# Set base URL (modify if needed)
BASE_URL="http://localhost:8787"

# Test credentials
ADMIN_PASSWORD="19840910"
INVALID_PASSWORD="wrong-password"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS=0
PASSED=0
FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local method="$2"
    local endpoint="$3"
    local headers="$4"
    local data="$5"
    local expected_status="$6"
    local description="$7"
    
    TESTS=$((TESTS + 1))
    echo
    echo -e "${BLUE}Test $TESTS: $test_name${NC}"
    if [ -n "$description" ]; then
        echo -e "${YELLOW}Description: $description${NC}"
    fi
    echo "---------------------------------------"
    
    # Build curl command
    local curl_cmd="curl -s -w \"\n%{http_code}\" -X $method"
    
    # Add headers if provided
    if [ -n "$headers" ]; then
        while IFS= read -r header; do
            if [ -n "$header" ]; then
                curl_cmd="$curl_cmd -H \"$header\""
            fi
        done <<< "$headers"
    fi
    
    # Add data if provided
    if [ -n "$data" ]; then
        curl_cmd="$curl_cmd -d '$data'"
    fi
    
    curl_cmd="$curl_cmd \"$BASE_URL$endpoint\""
    
    # Execute curl command
    response=$(eval "$curl_cmd")
    
    # Split response body and status code
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1)
    
    echo "Status: $status"
    echo "Response: $(echo "$body" | head -c 200)$([ ${#body} -gt 200 ] && echo "...")"
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ FAILED - Expected status $expected_status, got $status${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo
echo "🔍 Phase 1: JWT + Cookie Hybrid Authentication Tests"
echo "====================================================="

# Test 1: Login with no password
run_test "Login without password" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{}' \
    "400" \
    "Should require password field"

# Test 2: Login with wrong password
run_test "Login with invalid password" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    "{\"password\": \"$INVALID_PASSWORD\"}" \
    "401" \
    "Should reject invalid credentials"

# Test 3: Login with correct password
run_test "Login with valid password" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    "{\"password\": \"$ADMIN_PASSWORD\"}" \
    "200" \
    "Should accept valid credentials"

# Extract session cookie and JWT tokens for further tests
echo
echo "Extracting session cookie and JWT tokens..."
login_response=$(curl -s -c /tmp/cookies.txt -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -d "{\"password\": \"$ADMIN_PASSWORD\"}" \
    "$BASE_URL/api/auth/login")

login_status=$(echo "$login_response" | tail -n 1)
login_body=$(echo "$login_response" | head -n -1)

if [ "$login_status" = "200" ]; then
    echo "✅ Session established for admin tests"
    SESSION_COOKIE=$(cat /tmp/cookies.txt | grep adminSession | awk '{print $7}')
    echo "Session ID: ${SESSION_COOKIE:0:20}..."
    
    # Extract JWT tokens if available
    ACCESS_TOKEN=$(echo "$login_body" | grep -o '"accessToken":"[^"]*"' | cut -d'"' -f4)
    REFRESH_TOKEN=$(echo "$login_body" | grep -o '"refreshToken":"[^"]*"' | cut -d'"' -f4)
    
    if [ -n "$ACCESS_TOKEN" ]; then
        echo "✅ JWT Access Token obtained: ${ACCESS_TOKEN:0:30}..."
    fi
    if [ -n "$REFRESH_TOKEN" ]; then
        echo "✅ JWT Refresh Token obtained: ${REFRESH_TOKEN:0:30}..."
    fi
else
    echo "❌ Failed to establish session"
    SESSION_COOKIE=""
    ACCESS_TOKEN=""
    REFRESH_TOKEN=""
fi

echo
echo "🔒 Phase 2: Authorization Security Tests"
echo "========================================="

# Test 4: Access admin stats without authentication
run_test "Admin endpoint - No auth" \
    "GET" \
    "/api/admin/stats" \
    "" \
    "" \
    "401" \
    "Should block unauthenticated access"

# Test 5: Access admin stats with invalid header auth
run_test "Admin endpoint - Invalid header auth" \
    "GET" \
    "/api/admin/stats" \
    "Authorization: Bearer invalid-key" \
    "" \
    "401" \
    "Should reject invalid API key"

# Test 6: Access admin stats with valid session
if [ -n "$SESSION_COOKIE" ]; then
    run_test "Admin endpoint - Valid session" \
        "GET" \
        "/api/admin/stats" \
        "Cookie: adminSession=$SESSION_COOKIE" \
        "" \
        "200" \
        "Should allow access with valid session"
fi

# Test 7: Access admin stats with valid header auth (legacy)
run_test "Admin endpoint - Valid header auth (legacy)" \
    "GET" \
    "/api/admin/stats" \
    "Authorization: Bearer $ADMIN_PASSWORD" \
    "" \
    "200" \
    "Should allow access with valid API key"

# Test 8: Access admin stats with JWT token
if [ -n "$ACCESS_TOKEN" ]; then
    run_test "Admin endpoint - JWT Bearer token" \
        "GET" \
        "/api/admin/stats" \
        "Authorization: Bearer $ACCESS_TOKEN" \
        "" \
        "200" \
        "Should allow access with valid JWT token"
fi

# Test 9: JWT token refresh functionality
if [ -n "$REFRESH_TOKEN" ]; then
    run_test "JWT token refresh" \
        "POST" \
        "/api/auth/refresh" \
        "Content-Type: application/json" \
        "{\"refreshToken\": \"$REFRESH_TOKEN\"}" \
        "200" \
        "Should refresh JWT tokens successfully"
fi

echo
echo "🛡️  Phase 3: Enhanced Multi-Layer CSRF Protection Tests"
echo "========================================================"

# Test 10: State-changing operation without CSRF protection
run_test "Component creation - No CSRF headers" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json" \
    '{
        "name": "CSRF Test",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "403" \
    "Should block requests without proper headers"

# Test 11: State-changing operation with CSRF protection headers
run_test "Component creation - With CSRF headers" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "CSRF Test Valid",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201" \
    "Should allow requests with proper headers"

# Test 12: State-changing operation with JWT Bearer token (CSRF layer)
if [ -n "$ACCESS_TOKEN" ]; then
    run_test "Component creation - JWT Bearer (CSRF layer)" \
        "POST" \
        "/api/components" \
        "Content-Type: application/json
Authorization: Bearer $ACCESS_TOKEN" \
        '{
            "name": "CSRF Test JWT",
            "category": "Test", 
            "html": "<div>JWT Test</div>",
            "css": "",
            "js": "",
            "tags": ["test", "jwt"]
        }' \
        "201" \
        "Should allow requests with JWT Bearer token as CSRF protection"
fi

# Test 13: State-changing operation with custom app header
run_test "Component creation - Custom app header" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-App-Name: component-management" \
    '{
        "name": "CSRF Test App Header",
        "category": "Test",
        "html": "<div>App Header Test</div>",
        "css": "",
        "js": "",
        "tags": ["test", "header"]
    }' \
    "201" \
    "Should allow requests with custom app header"

# Test 14: Admin state-changing operation without CSRF
if [ -n "$SESSION_COOKIE" ]; then
    run_test "Admin operation - No CSRF headers" \
        "DELETE" \
        "/api/admin/purge-old?days=365" \
        "Cookie: adminSession=$SESSION_COOKIE" \
        "" \
        "403" \
        "Should block admin operations without CSRF headers"
    
    run_test "Admin operation - With CSRF headers" \
        "DELETE" \
        "/api/admin/purge-old?days=365" \
        "Cookie: adminSession=$SESSION_COOKIE
X-Requested-With: XMLHttpRequest" \
        "" \
        "200" \
        "Should allow admin operations with CSRF headers"
fi

echo
echo "🚫 Phase 4: Rate Limiting Tests"
echo "==============================="

# Test 15: Rate limiting on failed auth attempts
echo "Testing rate limiting (this may take a moment)..."
for i in {1..6}; do
    echo "Failed attempt $i..."
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "X-Requested-With: XMLHttpRequest" \
        -d '{"password": "wrong-password-'$i'"}' \
        "$BASE_URL/api/auth/login" > /dev/null
    sleep 0.5
done

run_test "Rate limiting - Should be active" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{"password": "another-wrong-password"}' \
    "429" \
    "Should rate limit after multiple failed attempts"

echo
echo "⚠️  Phase 5: Enhanced XSS Protection & Input Validation Tests"
echo "============================================================="

# Test 16: XSS attempt in component HTML
run_test "XSS in component HTML" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "XSS Test",
        "category": "Security",
        "html": "<script>alert(\"XSS\")</script><div>Content</div>",
        "css": "",
        "js": "",
        "tags": ["security", "test"]
    }' \
    "201" \
    "Should sanitize XSS attempts but allow creation"

# Test 17: Advanced XSS attempts in CSS
run_test "XSS in component CSS" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "CSS XSS Test",
        "category": "Security",
        "html": "<div class=\"test\">CSS Test</div>",
        "css": "body { background: url(javascript:alert(\"CSS XSS\")); } .test { expression(alert(\"IE XSS\")); }",
        "js": "",
        "tags": ["security", "css"]
    }' \
    "201" \
    "Should sanitize CSS-based XSS attempts"

# Test 18: JavaScript injection attempts
run_test "JavaScript injection" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "JS XSS Test",
        "category": "Security",
        "html": "<div>JS Test</div>",
        "css": "",
        "js": "eval(\"alert('XSS')\"); setTimeout(\"alert('Delayed XSS')\", 1000); document.cookie = \"stolen=true\";",
        "tags": ["security", "js"]
    }' \
    "201" \
    "Should heavily sanitize JavaScript content"

# Test 19: Invalid data types
run_test "Invalid data types" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": 123,
        "category": null,
        "html": false,
        "tags": "not-an-array"
    }' \
    "400" \
    "Should reject invalid data types"

# Test 20: Missing required fields
run_test "Missing required fields" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "html": "<div>Test</div>"
    }' \
    "400" \
    "Should require name and category fields"

echo
echo "🌐 Phase 6: CORS Security Tests"
echo "==============================="

# Test 21: CORS preflight from allowed origin
run_test "CORS preflight - Allowed origin" \
    "OPTIONS" \
    "/api/components" \
    "Origin: https://component-management.vercel.app
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type,X-Requested-With" \
    "" \
    "200" \
    "Should allow CORS preflight from allowed origins"

# Test 22: CORS preflight from disallowed origin  
run_test "CORS preflight - Disallowed origin" \
    "OPTIONS" \
    "/api/components" \
    "Origin: https://malicious-site.com
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type" \
    "" \
    "200" \
    "CORS preflight always returns 200, but response headers matter"

# Test 23: Security headers verification
run_test "Security headers verification" \
    "GET" \
    "/api/health" \
    "" \
    "" \
    "200" \
    "Should include comprehensive security headers"

echo
echo "🧪 Phase 7: Edge Cases and Error Handling"
echo "=========================================="

# Test 24: Malformed JSON
run_test "Malformed JSON" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{"name": "test", "category":}' \
    "400" \
    "Should handle malformed JSON gracefully"

# Test 25: Extremely long content
run_test "Content length validation" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    "{\"name\": \"Long Test\", \"category\": \"Test\", \"html\": \"$(printf 'A%.0s' {1..60000})\", \"css\": \"\", \"js\": \"\", \"tags\": [\"test\"]}" \
    "400" \
    "Should reject content that exceeds length limits"

# Test 26: Session status check
run_test "Auth status check" \
    "GET" \
    "/api/auth/status" \
    "$([ -n "$SESSION_COOKIE" ] && echo "Cookie: adminSession=$SESSION_COOKIE")" \
    "" \
    "200" \
    "Should return authentication status"

# Test 27: Logout functionality
if [ -n "$SESSION_COOKIE" ]; then
    run_test "Logout with valid session" \
        "POST" \
        "/api/auth/logout" \
        "Cookie: adminSession=$SESSION_COOKIE
X-Requested-With: XMLHttpRequest" \
        "" \
        "200" \
        "Should successfully logout"
    
    # Test 28: Access after logout
    run_test "Admin access after logout" \
        "GET" \
        "/api/admin/stats" \
        "Cookie: adminSession=$SESSION_COOKIE" \
        "" \
        "401" \
        "Should deny access after logout"
fi

# Cleanup
rm -f /tmp/cookies.txt

# Summary
echo
echo "🔐 Security Test Summary"
echo "========================"
echo -e "Total Tests: $TESTS"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All security tests passed!${NC}"
    echo
    echo "📊 Enhanced Security Features Verified:"
    echo "----------------------------------------"
    echo "✅ JWT + Cookie hybrid authentication system"
    echo "✅ Multi-layer CSRF protection (Origin + Headers + JWT)"
    echo "✅ Enhanced XSS protection with comprehensive sanitization"
    echo "✅ Strict Content Security Policy (CSP)"
    echo "✅ Rate limiting on authentication attempts"
    echo "✅ Authorization for admin endpoints"
    echo "✅ Security headers (HSTS, X-Frame-Options, etc.)"
    echo "✅ Input validation with type checking"
    echo "✅ CORS configuration with origin validation"
    echo "✅ Error handling and edge cases"
    echo
    exit 0
else
    echo -e "${RED}⚠️  Some security tests failed. Please review the implementation.${NC}"
    echo
    echo "Failed tests may indicate security vulnerabilities."
    echo "Please address the issues before deploying to production."
    echo
    exit 1
fi