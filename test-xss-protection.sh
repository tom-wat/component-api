#!/bin/bash

# XSS Protection Test Script
# Tests the new validation and sanitization features

echo "🔒 XSS Protection Test Suite"
echo "================================"

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
    local data="$4"
    local expected_status="$5"
    
    TESTS=$((TESTS + 1))
    echo
    echo "Test $TESTS: $test_name"
    echo "---------------------------------------"
    
    if [ "$method" = "POST" ]; then
        response=$(curl -s -w "\n%{http_code}" -X POST \
            -H "Content-Type: application/json" \
            -H "X-Requested-With: XMLHttpRequest" \
            -d "$data" \
            "$BASE_URL$endpoint")
    elif [ "$method" = "PUT" ]; then
        response=$(curl -s -w "\n%{http_code}" -X PUT \
            -H "Content-Type: application/json" \
            -H "X-Requested-With: XMLHttpRequest" \
            -d "$data" \
            "$BASE_URL$endpoint")
    else
        response=$(curl -s -w "\n%{http_code}" "$BASE_URL$endpoint")
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
echo "Testing XSS Protection Implementation..."
echo

# Test 1: Basic component creation (should pass)
run_test "Valid Component Creation" \
    "POST" \
    "/api/components" \
    '{
        "name": "Test Button",
        "category": "UI",
        "html": "<button class=\"btn\">Click me</button>",
        "css": ".btn { background: blue; color: white; }",
        "js": "console.log(\"Hello World\");",
        "tags": ["button", "ui"]
    }' \
    "201"

# Test 2: XSS in HTML (should be sanitized)
run_test "XSS Script Tag in HTML" \
    "POST" \
    "/api/components" \
    '{
        "name": "XSS Test",
        "category": "Test",
        "html": "<div>Hello <script>alert(\"XSS\")</script> World</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 3: XSS Event Handler (should be sanitized)
run_test "XSS Event Handler in HTML" \
    "POST" \
    "/api/components" \
    '{
        "name": "Event Handler Test",
        "category": "Test",
        "html": "<button onclick=\"alert(\\\"XSS\\\")\">Click me</button>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 4: Malicious CSS (should be sanitized)
run_test "CSS Injection Test" \
    "POST" \
    "/api/components" \
    '{
        "name": "CSS Test",
        "category": "Test",
        "html": "<div class=\"test\">Test</div>",
        "css": ".test { background: url(javascript:alert(\"XSS\")); }",
        "js": "",
        "tags": ["test"]
    }' \
    "201"

# Test 5: Malicious JavaScript (should be sanitized)
run_test "JS Injection Test" \
    "POST" \
    "/api/components" \
    '{
        "name": "JS Test",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "eval(\"alert(\\\"XSS\\\")\"); document.cookie = \"stolen\";",
        "tags": ["test"]
    }' \
    "201"

# Test 6: Name validation (should fail)
run_test "Empty Name Validation" \
    "POST" \
    "/api/components" \
    '{
        "name": "",
        "category": "Test",
        "html": "<div>Test</div>",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "400"

# Test 7: Long content validation (should fail)
run_test "Content Length Validation" \
    "POST" \
    "/api/components" \
    '{
        "name": "Long Content Test",
        "category": "Test",
        "html": "'$(printf 'A%.0s' {1..60000})'",
        "css": "",
        "js": "",
        "tags": ["test"]
    }' \
    "400"

# Test 8: Invalid JSON structure (should fail)
run_test "Invalid Data Structure" \
    "POST" \
    "/api/components" \
    '{
        "name": 123,
        "category": null,
        "html": false,
        "tags": "not-an-array"
    }' \
    "400"

# Test 9: Health check (should still work)
run_test "Health Check Still Works" \
    "GET" \
    "/api/health" \
    "" \
    "200"

# Summary
echo
echo "🔒 XSS Protection Test Summary"
echo "=============================="
echo -e "Total Tests: $TESTS"
echo -e "${GREEN}Passed: $PASSED${NC}"
echo -e "${RED}Failed: $FAILED${NC}"

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}🎉 All tests passed! XSS protection is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}⚠️  Some tests failed. Please check the implementation.${NC}"
    exit 1
fi