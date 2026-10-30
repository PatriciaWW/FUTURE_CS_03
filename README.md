# API Security Risk Analysis

## Overview

This project documents a security assessment of the JSONPlaceholder REST API, a public demo API used for testing and development.

The assessment focused on identifying common API security risks such as missing authentication and authorization, weak input validation, excessive data exposure, and security header issues.

All testing was performed using read-only and non-destructive requests where possible. No real user data or production systems were targeted.

## Objectives

The main objectives of this assessment were to:

- Test whether API endpoints require authentication.
- Check authorization controls for accessing and modifying resources.
- Assess input validation.
- Identify excessive data exposure.
- Review HTTP security headers.
- Check how the API handles invalid requests and errors.
- Document identified risks and their potential impact.

## Tools Used

- **Postman** – API requests and testing
- **JSONPlaceholder** – Target API
- **Git/GitHub** – Version control and documentation

## API Endpoints Tested

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/posts` | Retrieve posts |
| GET | `/posts/1` | Retrieve a specific post |
| POST | `/posts` | Create a post |
| PUT | `/posts/1` | Update a post |
| DELETE | `/posts/1` | Delete a post |
| GET | `/users/1` | Retrieve user information |
| GET | `/posts/99999` | Test nonexistent resource handling |

## Key Findings

### 1. Missing Authentication

Several endpoints allowed access without requiring authentication.

This means a client can interact with API resources without providing valid credentials.

**Risk:** High

### 2. Missing Authorization / Access Control

The API accepted requests to create, update, and delete resources without verifying whether the requester had permission to perform those actions.

**Risk:** High

### 3. Invalid Authorization Token Ignored

Adding a random `Authorization` header did not cause the API to reject the request.

This indicates that the supplied authorization token is not actually being validated.

**Risk:** High

### 4. Weak Input Validation

The API accepted incorrectly typed values. For example:

```json
{
  "userId": "HELLO"
}