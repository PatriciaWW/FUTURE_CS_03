# Findings Log

**Project:** API Security Risk Analysis
**Target:** https://jsonplaceholder.typicode.com
**Tester:** Patricia Wanjiru Wachira
**Dates tested:** 22 to 30 October 2026
**Tool:** Postman (post-response test script for auth and header checks)
**Scope reminder:** Read-only testing of a public/demo API. One request per test, no flooding, no exploitation or bypass attempts.

---

## 1. Request Log (one row per request)

| # | Method | Endpoint | Auth sent? | Status | Observation | Suggested screenshot name |
|---|---|---|---|---|---|---|
| 1 | GET | `/posts/1` | No | 200 OK | Data returned with no credentials. 1.08 KB, 94 ms. Test results 5/6; HSTS check failed. | `01-get-posts1.png` |
| 2 | POST | `/posts` | No | 201 Created | Create accepted with no credentials (first run, body not captured). 1.3 KB, 840 ms. Test results 4/6. The "returned data" test failed only because the script expects 200, so this is a finding, not a pass. | `02-post-posts-initial.png` |
| 3 | PUT | `/comments?postId=1` | No | 404 Not Found | INCONCLUSIVE. PUT was sent to a filtered collection, not a single resource. Excluded from findings; repeated correctly as #5. | `03-put-comments-404.png` |
| 4 | DELETE | `/users/1` | No | 200 OK | Delete accepted with no credentials. 1.36 s, 900 B. Test results 5/6. | `04-delete-users1.png` |
| 5 | PUT | `/posts/1` | No | 200 OK | Update accepted with no credentials. Submitted body (`id`, `title`, `body`, `userId`) echoed back. 792 ms, 958 B. Test results 5/6. | `05-put-posts1.png` |
| 6 | GET | `/users/1` | No | 200 OK | Full user profile returned: name, username, email, address (street, suite, city, zipcode), geo lat/lng, phone, website, company. 1.79 s, 1.21 KB. | `06-get-users1.png` |
| 7 | GET | `/posts?userId=2` | No | 200 OK | Posts belonging to user 2 (ids 11, 12, 13 ...) returned with no ownership check. 146 ms, 1.87 KB. Test results 5/6. | `07-get-posts-userid2.png` |
| 8 | POST | `/posts` | No | 201 Created | Post accepted with `userId` 555, a user that does not exist. Response echoed the values and assigned `id` 101. 522 ms, 1.29 KB. Test results 4/6. | `08-post-posts-userid555.png` |
| 9 | (fill in) | (fill in endpoint) | Fabricated `Authorization` header | (fill in) | A random token was added to the request. The header was ignored and the response was the same as without it. | `09-fake-auth-header.png` |
| 10 | POST | `/posts` | No | Created | `userId` sent as `"HELLO"` (wrong data type). The post was still created with no validation error. | `10-post-userid-hello.png` |
| 11 | GET | non-existent post (fill in the id used) | No | 404 Not Found | Generic 404 only. No stack trace, file path or internal detail in the response. | `11-get-nonexistent-post-404.png` |
| 12 | | | | | | |

**Supporting evidence:** the request Headers tab for the POST (9 auto-generated headers, no `Authorization` header) confirms no credentials were sent. Suggested name: `09-post-request-headers.png`.

**Header checks (script):** `Strict-Transport-Security` failed on the requests where the script ran. `X-Content-Type-Options` and `X-RateLimit-Limit` were detected. The script did not run on request 6 (Test Results shows no count).

**Response header values (Headers tab):** rate-limit header value `3600000`; `Access-Control-Allow-Origin` not returned. Suggested screenshot name: `12-response-headers.png`.

---

## 2. Findings Summary

| ID | Title | Location | Severity | OWASP / category | Status |
|---|---|---|---|---|---|
| API-01 | Unauthenticated read access | `GET /posts/1` | Medium (High if real data) | API2:2023 Broken Authentication | Open |
| API-02 | Unauthenticated record creation | `POST /posts` | High | API2:2023, API5:2023 | Open |
| API-03 | Unauthenticated record update | `PUT /posts/1` | High | API2:2023, API5:2023 | Open |
| API-04 | Unauthenticated record deletion | `DELETE /users/1` | High | API2:2023, API5:2023 | Open |
| API-05 | Excessive exposure of user data | `GET /users/1` | High | API3:2023 Broken Object Property Level Authorization | Open |
| API-06 | No object-level access control | `GET /posts?userId=2` | Medium (High if private data) | API1:2023 Broken Object Level Authorization | Open |
| API-07 | Weak input validation | `POST /posts` (userId 555 and "HELLO") | Medium | Improper Input Validation (CWE-20) | Open |
| API-08 | Missing HSTS header | Responses checked | Low | API8:2023 Security Misconfiguration | Open |
| API-09 | Fabricated authorization token ignored | Any request with a made-up `Authorization` header | High | API2:2023 Broken Authentication | Open |
| API-10 | Very high rate limit | Response rate-limit header | Low | API4:2023 Unrestricted Resource Consumption | Open |
| API-11 | | | | | |

**Totals:** High: 5 | Medium: 3 | Low: 2 | Inconclusive: 1 (request 3, superseded by request 5)

---

## 3. Detailed Findings

### API-01: Unauthenticated read access

| Field | Detail |
|---|---|
| **Location** | `GET /posts/1` |
| **Category** | API2:2023 Broken Authentication |
| **Severity** | Medium for this demo API; High if it served customer data |
| **Description** | The endpoint returns data with no Authorization header or API key. |
| **Evidence** | `200 OK`, no credentials sent. Screenshot: `01-get-posts1.png` |
| **Business impact** | Anyone can read data without identifying themselves, so access cannot be attributed, limited or revoked. |
| **Remediation** | Require token-based authentication (OAuth 2.0 / JWT) on every non-public endpoint, with least-privilege scopes. |
| **Notes** | Expected by design on a demo API. Rated as it would be in production. |

### API-02: Unauthenticated record creation

| Field | Detail |
|---|---|
| **Location** | `POST /posts` |
| **Category** | API2:2023 Broken Authentication; API5:2023 Broken Function Level Authorization |
| **Severity** | High |
| **Description** | The API accepted create requests with no credentials and returned `201 Created`. |
| **Evidence** | `201 Created` on requests 2 and 8. Screenshots: `02-post-posts-initial.png`, `08-post-posts-userid555.png`, `09-post-request-headers.png` (no Authorization header) |
| **Business impact** | Anyone could insert records: spam, data pollution, fake records, extra storage and processing cost. |
| **Remediation** | Require authentication on all write methods, check the caller may create that resource, then validate and rate-limit the request. |
| **Notes** | JSONPlaceholder fakes writes (nothing is saved). The returned `id` 101 is the next number after its 100 sample posts. |

### API-03: Unauthenticated record update

| Field | Detail |
|---|---|
| **Location** | `PUT /posts/1` |
| **Category** | API2:2023 Broken Authentication; API5:2023 Broken Function Level Authorization |
| **Severity** | High |
| **Description** | The API accepted an update to an existing post with no credentials and returned `200 OK` with the submitted body. |
| **Evidence** | `200 OK`, 792 ms, no credentials sent. Screenshot: `05-put-posts1.png` |
| **Business impact** | Attackers could alter existing records, tampering with content or user data and undermining data integrity. |
| **Remediation** | Require authentication, enforce ownership or role checks before any update, and log who changed what and when. |
| **Notes** | Replaces the inconclusive PUT in request 3. Writes are faked by the sandbox. |

### API-04: Unauthenticated record deletion

| Field | Detail |
|---|---|
| **Location** | `DELETE /users/1` |
| **Category** | API2:2023 Broken Authentication; API5:2023 Broken Function Level Authorization |
| **Severity** | High |
| **Description** | The API accepted a delete request for a user record with no credentials and returned `200 OK`. |
| **Evidence** | `200 OK`, 1.36 s, no credentials sent. Screenshot: `04-delete-users1.png` |
| **Business impact** | Anonymous callers could remove user data in production: data loss, service disruption, legal and reputational damage. |
| **Remediation** | Restrict deletes to authenticated users with explicit permission, enforce record ownership, log every delete, and alert on bulk deletions. |
| **Notes** | Writes are faked by the sandbox. |

### API-05: Excessive exposure of user data

| Field | Detail |
|---|---|
| **Location** | `GET /users/1` |
| **Category** | API3:2023 Broken Object Property Level Authorization (excessive data exposure) |
| **Severity** | High (the demo data is fictional; rated as production personal data) |
| **Description** | An unauthenticated request returns the full user object: `name`, `username`, `email`, full `address` including `zipcode` and `geo` coordinates, `phone`, `website`, and `company` details. |
| **Evidence** | `200 OK`, 1.21 KB, 1.79 s. Screenshot: `06-get-users1.png` |
| **Business impact** | Anonymous exposure of personal and contact data enables phishing, identity fraud and stalking, and can breach data protection law (for example Kenya's Data Protection Act, 2019, or GDPR), with fines and loss of customer trust. |
| **Remediation** | Return only the fields each client needs (response shaping), require authentication, restrict sensitive fields by role, and review every endpoint for data minimization. |
| **Notes** | |

### API-06: No object-level access control

| Field | Detail |
|---|---|
| **Location** | `GET /posts?userId=2` |
| **Category** | API1:2023 Broken Object Level Authorization |
| **Severity** | Medium for this demo API; High if the objects were private |
| **Description** | Changing the `userId` value returns another user's posts. No identity is checked, so the API cannot confirm the caller may see that user's data. |
| **Evidence** | `200 OK`, 146 ms, 1.87 KB, posts with `userId` 2. Screenshot: `07-get-posts-userid2.png` |
| **Business impact** | Any caller can walk through predictable numeric ids and collect other customers' records. |
| **Remediation** | Enforce object-level authorization on the server for every request, take the user identity from the token rather than client-supplied ids, and consider non-sequential identifiers (UUIDs) as defense in depth. |
| **Notes** | Only tested on posts. `GET /users/2` could be added as an optional check. |

### API-07: Weak input validation

| Field | Detail |
|---|---|
| **Location** | `POST /posts` with `userId` 555 |
| **Category** | Improper Input Validation (CWE-20) |
| **Severity** | Medium |
| **Description** | The API accepted a new post for `userId` 555, a user that does not exist in the dataset, and also accepted `userId` sent as the text `"HELLO"` instead of a number. Both posts were created with no validation error. |
| **Evidence** | `201 Created`, 522 ms, response echoed the values and assigned `id` 101 (`08-post-posts-userid555.png`). The `"HELLO"` request also created the post (`10-post-userid-hello.png`). |
| **Business impact** | Invalid or orphaned records can corrupt data, break application logic, and often signal wider validation gaps that attackers exploit. |
| **Remediation** | Validate requests server-side (data types, ranges, required fields), check that referenced users exist and that the caller may act for them, and return `400` or `422` for invalid input. |
| **Notes** | Wrong data type and non-existent reference both tested. Special characters and oversized values were not. |

### API-08: Missing HTTP Strict Transport Security (HSTS)

| Field | Detail |
|---|---|
| **Location** | Responses checked by the script |
| **Category** | API8:2023 Security Misconfiguration |
| **Severity** | Low |
| **Description** | The `Strict-Transport-Security` response header is not set. |
| **Evidence** | Header check failed in the Postman test results. Screenshot: `01-get-posts1.png` |
| **Business impact** | Clients may be tricked into using plain HTTP, exposing traffic to interception on hostile networks. |
| **Remediation** | Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` and serve HTTPS only. |
| **Notes** | A Headers-tab screenshot of the response would strengthen this evidence. |

### API-09: Fabricated authorization token ignored

| Field | Detail |
|---|---|
| **Location** | Requests sent with a made-up `Authorization` header (fill in the endpoint used) |
| **Category** | API2:2023 Broken Authentication |
| **Severity** | High |
| **Description** | When a random `Authorization` value is added to a request, the API ignores it and responds exactly as it does with no header. Tokens are never validated. |
| **Evidence** | Request 9: the response was the same with and without the fabricated token. Screenshot: `09-fake-auth-header.png` |
| **Business impact** | Developers may believe requests are protected when they are not, and any attacker can send any value as a token and be treated as legitimate. In production this would be a complete authentication bypass. |
| **Remediation** | Validate the token (signature, expiry, issuer and audience) on every request, reject missing or invalid tokens with `401 Unauthorized`, and test that fabricated tokens are refused. |
| **Notes** | Same root cause as API-01 to API-04 (no authentication at all), but shown from the token side. |

### API-10: Very high rate limit

| Field | Detail |
|---|---|
| **Location** | Response rate-limit header |
| **Category** | API4:2023 Unrestricted Resource Consumption |
| **Severity** | Low (based on the header value; enforcement was not tested) |
| **Description** | The API returns a rate-limit header with the value `3600000`. If this is the per-window request allowance, it is too high to restrict any single client, so rate limiting gives little practical protection. |
| **Evidence** | Response Headers tab: rate-limit header `3600000`. Screenshot: `12-response-headers.png` |
| **Business impact** | Without effective limits, one client can scrape the whole dataset, overload the service or run up hosting costs. With no authentication, abuse cannot be throttled per user. |
| **Remediation** | Set realistic per-client limits (per API key or IP address), return `429 Too Many Requests` with a `Retry-After` header when exceeded, and monitor for unusual traffic. |
| **Notes** | Confirm which header holds `3600000` (limit, remaining or reset) and record its exact name. |


## 4. Positive Observations

- `X-Content-Type-Options` present on the responses checked.
- A request for a non-existent post returned a generic `404 Not Found` with no stack trace or internal details (good error handling).
- No `Access-Control-Allow-Origin` header was returned on the request tested, so no wildcard cross-origin access was observed.
- All requests were served over HTTPS.

---

## 5. Checks Still To Do

- [ ] Screenshot the new tests so each finding has evidence: fabricated token (`09`), `"HELLO"` POST (`10`), non-existent post 404 (`11`), response Headers tab (`12`)
- [ ] Fill in the endpoint and method used for request 9, and the post id used for request 11
- [ ] Confirm which header holds `3600000` and write its exact name
- [ ] Optional: send `Access-Control-Allow-Origin` check with an `Origin` header to see if CORS is returned
- [ ] Optional: `GET /users/2` for object-level access on users
- [ ] Optional: `http://` version of the URL, check for an HTTPS redirect

---

## 6. Severity Guide

| Level | Meaning |
|---|---|
| **High** | Easy to abuse and exposes sensitive data or lets attackers modify it |
| **Medium** | Needs some conditions, or exposes limited data |
| **Low** | Hardening or best-practice gap with little direct impact |

