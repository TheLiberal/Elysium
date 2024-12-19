#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# Base URL
API_URL="http://localhost:3000"

# Store cookies
COOKIE_JAR="/tmp/cookies.txt"

echo -e "${GREEN}Testing API Endpoints${NC}\n"

# 1. Health Check
echo "Testing Health Check..."
curl -s "$API_URL/health" | jq .

# 2. Create User
echo -e "\nCreating User..."
SIGNUP_RESPONSE=$(curl -s -X POST "$API_URL/auth/signup" \
  -H "Content-Type: application/json" \
  -c "$COOKIE_JAR" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }')

echo $SIGNUP_RESPONSE | jq .

# 3. Login
echo -e "\nTesting Login..."
LOGIN_RESPONSE=$(curl -s -X POST "$API_URL/auth/login" \
  -H "Content-Type: application/json" \
  -c "$COOKIE_JAR" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }')

echo $LOGIN_RESPONSE | jq .

# 4. Protected Route
echo -e "\nTesting Protected Route..."
curl -s "$API_URL/api/protected" \
  -b "$COOKIE_JAR" | jq .

# 5. Get User Profile
echo -e "\nGetting User Profile..."
curl -s "$API_URL/api/me" \
  -b "$COOKIE_JAR" | jq .

# 6. Refresh Token (cookies are handled automatically)
echo -e "\nTesting Token Refresh..."
REFRESH_RESPONSE=$(curl -s -X POST "$API_URL/auth/refresh" \
  -b "$COOKIE_JAR" \
  -c "$COOKIE_JAR")

echo $REFRESH_RESPONSE | jq .

# 7. Logout
echo -e "\nTesting Logout..."
curl -s -X POST "$API_URL/auth/logout" \
  -b "$COOKIE_JAR" | jq .

# Clean up
rm -f "$COOKIE_JAR"

echo -e "\n${GREEN}Testing Complete!${NC}" 