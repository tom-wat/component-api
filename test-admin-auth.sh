#!/bin/bash

# Admin Authentication Test Script
# Tests the new admin endpoint protection

echo "🔐 Admin Authentication Test Suite"
echo "===================================="

# Set base URL (modify if needed)
BASE_URL="http://localhost:8787"

# Test API key (from wrangler.toml development config)
ADMIN_KEY="dev-admin-key-12345"
INVALID_KEY="wrong-key-123"

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
    local auth_header="$4"
    local expected_status="$5"
    
    TESTS=$((TESTS + 1))
    echo
    echo "Test $TESTS: $test_name"
    echo "---------------------------------------"
    
    if [ -n "$auth_header" ]; then
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            -H "$auth_header" \
            "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" \
            "$BASE_URL$endpoint")
    fi
    
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
echo "Testing Admin Endpoint Protection..."
echo

# Test 1: Access admin stats without authentication (should fail)
run_test "Admin Stats - No Auth" \
    "GET" \
    "/api/admin/stats" \
    "" \
    "401"

# Test 2: Access admin stats with invalid API key (should fail)
run_test "Admin Stats - Invalid Key" \
    "GET" \
    "/api/admin/stats" \
    "Authorization: Bearer $INVALID_KEY" \
    "403"

# Test 3: Access admin stats with valid API key via Authorization header (should pass)
run_test "Admin Stats - Valid Auth Header" \
    "GET" \
    "/api/admin/stats" \
    "Authorization: Bearer $ADMIN_KEY" \
    "200"

# Test 4: Access admin stats with valid API key via X-Admin-Key header (should pass)
run_test "Admin Stats - Valid X-Admin-Key Header" \
    "GET" \
    "/api/admin/stats" \
    "X-Admin-Key: $ADMIN_KEY" \
    "200"

# Test 5: Access deleted components without auth (should fail)
run_test "Deleted Components - No Auth" \
    "GET" \
    "/api/admin/deleted-components" \
    "" \
    "401"

# Test 6: Access deleted components with valid auth (should pass)
run_test "Deleted Components - Valid Auth" \
    "GET" \
    "/api/admin/deleted-components" \
    "Authorization: Bearer $ADMIN_KEY" \
    "200"

# Test 7: Access all components without auth (should fail)
run_test "All Components - No Auth" \
    "GET" \
    "/api/admin/all-components" \
    "" \
    "401"

# Test 8: Access all components with valid auth (should pass)
run_test "All Components - Valid Auth" \
    "GET" \
    "/api/admin/all-components" \
    "Authorization: Bearer $ADMIN_KEY" \
    "200"

# Test 9: Purge old components without auth (should fail)
run_test "Purge Old - No Auth" \
    "DELETE" \
    "/api/admin/purge-old?days=30" \
    "" \
    "401"

# Test 10: Purge old components with valid auth (should pass)
run_test "Purge Old - Valid Auth" \
    "DELETE" \
    "/api/admin/purge-old?days=30" \
    "Authorization: Bearer $ADMIN_KEY" \
    "200"

# Test 11: Public API still works without auth (should pass)
run_test "Public API - Health Check" \
    "GET" \
    "/api/health" \
    "" \
    "200"

# Test 12: Public API - Components list (should pass)
run_test "Public API - Components List" \
    "GET" \
    "/api/components" \
    "" \
    "200"

# Test 13: Multiple wrong attempts (should trigger rate limiting)
echo
echo "Testing Rate Limiting..."
echo "---------------------------------------"
for i in {1..6}; do
    echo "Attempt $i with wrong key..."
    curl -s -X GET \
        -H "Authorization: Bearer wrong-key-$i" \
        "$BASE_URL/api/admin/stats" > /dev/null
done

run_test "Rate Limiting - Should be blocked" \
    "GET" \
    "/api/admin/stats" \
    "Authorization: Bearer another-wrong-key" \
    "429"

# Summary
echo
echo "🔐 Admin Authentication Test Summary"
echo "====================================="
echo -e "Total Tests: $TESTS"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! Admin endpoints are properly protected.${NC}"
    echo
    echo "📋 Usage Instructions:"
    echo "----------------------"
    echo "To access admin endpoints, use one of these methods:"
    echo
    echo "Method 1 - Authorization Header:"
    echo "curl -H \"Authorization: Bearer $ADMIN_KEY\" $BASE_URL/api/admin/stats"
    echo
    echo "Method 2 - X-Admin-Key Header:"
    echo "curl -H \"X-Admin-Key: $ADMIN_KEY\" $BASE_URL/api/admin/stats"
    echo
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please check the implementation.${NC}"
    exit 1
fi