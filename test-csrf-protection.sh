#!/bin/bash

# CSRF Protection Test Script
# Tests the new CSRF protection implementation

echo "🛡️  CSRF Protection Test Suite"
echo "==============================="

# Set base URL (modify if needed)
BASE_URL="http://localhost:8787"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
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
    
    TESTS=$((TESTS + 1))
    echo
    echo "Test $TESTS: $test_name"
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
    
    echo "Command: $curl_cmd"
    
    # Execute curl command
    response=$(eval "$curl_cmd")
    
    # Split response body and status code
    body=$(echo "$response" | head -n -1)
    status=$(echo "$response" | tail -n 1)
    
    echo "Status: $status"
    echo "Response: $body"
    
    if [ "$status" = "$expected_status" ]; then
        echo -e "${GREEN}✅ PASSED${NC}"
        PASSED=$((PASSED + 1))
    else
        echo -e "${RED}❌ FAILED - Expected status $expected_status, got $status${NC}"
        FAILED=$((FAILED + 1))
    fi
}

echo
echo "Testing CSRF Protection Implementation..."
echo

# Test 1: POST without any headers (should fail CSRF protection)
run_test "POST without CSRF headers" \
    "POST" \
    "/api/components" \
    "" \
    '{
        "name": "Test Component",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "403"

# Test 2: POST with valid X-Requested-With header (should pass)
run_test "POST with X-Requested-With: XMLHttpRequest" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "Test Component XMLHttpRequest",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 3: POST with valid X-Requested-With: fetch (should pass)
run_test "POST with X-Requested-With: fetch" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-Requested-With: fetch" \
    '{
        "name": "Test Component Fetch",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 4: POST with custom X-App-Name header (should pass)
run_test "POST with X-App-Name: component-management" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
X-App-Name: component-management" \
    '{
        "name": "Test Component App",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 5: POST with valid Origin header (should pass)
run_test "POST with valid Origin header" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
Origin: https://component-management.vercel.app" \
    '{
        "name": "Test Component Origin",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 6: POST with invalid Origin header (should fail)
run_test "POST with invalid Origin header" \
    "POST" \
    "/api/components" \
    "Content-Type: application/json
Origin: https://malicious-site.com" \
    '{
        "name": "Test Component Malicious",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "403"

# Test 7: PUT without CSRF protection (should fail)
run_test "PUT without CSRF headers" \
    "PUT" \
    "/api/components/123" \
    "" \
    '{
        "name": "Updated Component"
    }' \
    "403"

# Test 8: PUT with valid headers (should pass to validation, might fail for other reasons)
run_test "PUT with valid CSRF headers" \
    "PUT" \
    "/api/components/123" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "name": "Updated Component"
    }' \
    "400"  # Might be 400 due to component not found, but not 403 for CSRF

# Test 9: DELETE without CSRF protection (should fail)
run_test "DELETE without CSRF headers" \
    "DELETE" \
    "/api/components/123" \
    "" \
    "" \
    "403"

# Test 10: DELETE with valid headers (should pass CSRF, might fail for other reasons)
run_test "DELETE with valid CSRF headers" \
    "DELETE" \
    "/api/components/123" \
    "X-Requested-With: XMLHttpRequest" \
    "" \
    "400"  # Might be 400 due to component not found, but not 403 for CSRF

# Test 11: GET requests should not be affected by CSRF protection
run_test "GET requests bypass CSRF protection" \
    "GET" \
    "/api/components" \
    "" \
    "" \
    "200"

# Test 12: OPTIONS requests should not be affected
run_test "OPTIONS requests bypass CSRF protection" \
    "OPTIONS" \
    "/api/components" \
    "Origin: https://malicious-site.com" \
    "" \
    "200"

# Test 13: Auth login with CSRF protection
run_test "Auth login without CSRF headers" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json" \
    '{
        "password": "test123"
    }' \
    "403"

# Test 14: Auth login with valid CSRF headers
run_test "Auth login with valid CSRF headers" \
    "POST" \
    "/api/auth/login" \
    "Content-Type: application/json
X-Requested-With: XMLHttpRequest" \
    '{
        "password": "test123"
    }' \
    "401"  # Should pass CSRF but fail auth

# Test 15: Admin endpoint CSRF protection (need valid admin auth for this)
echo
echo "Note: Admin endpoint tests require valid admin authentication"
echo "Setting up admin session first..."

# Try to get admin session (this might fail if no admin password is set)
ADMIN_PASSWORD="dev-admin-key-12345"
admin_response=$(curl -s -w "\n%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -H "X-Requested-With: XMLHttpRequest" \
    -d "{\"password\": \"$ADMIN_PASSWORD\"}" \
    "$BASE_URL/api/auth/login")

admin_status=$(echo "$admin_response" | tail -n 1)
if [ "$admin_status" = "200" ]; then
    echo "✅ Admin session established"
    
    # Extract cookies from response
    admin_cookies=$(echo "$admin_response" | head -n -1 | grep -o 'adminSession=[^;]*')
    
    run_test "Admin endpoint without CSRF headers" \
        "DELETE" \
        "/api/admin/purge-old?days=30" \
        "Cookie: $admin_cookies" \
        "" \
        "403"
    
    run_test "Admin endpoint with valid CSRF headers" \
        "DELETE" \
        "/api/admin/purge-old?days=30" \
        "Cookie: $admin_cookies
X-Requested-With: XMLHttpRequest" \
        "" \
        "200"
else
    echo "⚠️  Could not establish admin session, skipping admin CSRF tests"
fi

# Summary
echo
echo "🛡️  CSRF Protection Test Summary"
echo "================================="
echo -e "Total Tests: $TESTS"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! CSRF protection is working correctly.${NC}"
    echo
    echo "📋 CSRF Protection Summary:"
    echo "----------------------------"
    echo "✅ POST/PUT/DELETE requests require one of:"
    echo "   • Valid Origin/Referer from allowed domains"
    echo "   • X-Requested-With: XMLHttpRequest, fetch, application/json, or component-api"
    echo "   • X-App-Name: component-management"
    echo "   • Content-Type: application/json"
    echo "✅ GET/OPTIONS requests are not affected"
    echo "✅ Multi-layer protection implemented"
    echo
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please check the CSRF protection implementation.${NC}"
    exit 1
fi