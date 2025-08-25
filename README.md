# FastAPI Auth0 Token Verifier

A comprehensive demonstration of JWT and DPoP token verification using Auth0 with FastAPI, featuring support for both Regular Web Apps and SPAs with interactive Swagger UI documentation.

![Auth0](https://img.shields.io/badge/Auth0-Token%20Verification-orange)
![FastAPI](https://img.shields.io/badge/FastAPI-Framework-green)
![JWT](https://img.shields.io/badge/JWT-Verification-blue)
![DPoP (WIP)](https://img.shields.io/badge/DPoP-Support-purple)
![SPA](https://img.shields.io/badge/SPA-PKCE%20Support-red)

## 🎯 What This Demo Shows

This project demonstrates how to build secure APIs with comprehensive token verification:

- **JWT Token Verification** - Validate Auth0-issued access tokens
- **SPA Support** - Authorization Code + PKCE flow for Single Page Applications
- **Regular Web App Support** - Client Credentials flow for server-to-server
- **DPoP Authentication** - Enhanced security with proof-of-possession (WIP)
- **Configurable Scopes** - Dynamic scope selection through Swagger UI
- **User Profile Integration** - Automatic user data fetching from Auth0 /userinfo

## 🚀 Quick Start

### 1. Installation

```bash
# Clone the repository
git clone https://github.com/kishore7snehil/fastapi-auth0-token-verifier.git
cd fastapi-auth0-token-verifier

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your Auth0 settings:
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_AUDIENCE=https://your-api.example.com
```

### 3. Run the API

```bash
cd src/fastapi_auth0_token_verifier
python auth.py
```

### 4. Access Documentation

- **Swagger UI**: http://localhost:8000/docs
- **ReDoc**: http://localhost:8000/redoc
- **API Root**: http://localhost:8000/

## 🔐 Authentication Features

### Supported Authentication Schemes

| Scheme | Description | Use Case |
|--------|-------------|----------|
| **Auth0Bearer** | OAuth2 Client Credentials Flow | Server-to-server, machine-to-machine |
| **Auth0SPA** | OAuth2 Authorization Code + PKCE | Single Page Applications, mobile apps |
| **BearerAuth** | Standard JWT Bearer tokens | Direct token usage |
| **DPoP** | Proof-of-possession with ES256 signature | High-security environments (WIP) |

### API Endpoints

| Endpoint | Auth | Scope | Description |
|----------|------|-------|-------------|
| `GET /` | ✅ | - | API information and status |
| `GET /public` | ✅ | - | Public data access |
| `GET /protected` | ✅ | - | Basic protected resource with user profile |
| `GET /protected-with-scope` | ✅ | `read:users` | Scoped authorization demo |
| `GET /protected/dpop` | ❌ | - | DPoP authentication demo (WIP) |
| `GET /health` | ✅ | - | Service health check |

### Available Scopes (Configurable via Swagger UI)

| Scope | Description |
|-------|-------------|
| `openid` | OpenID Connect (enables user profile data) |
| `profile` | User profile information |
| `email` | User email address |
| `read:users` | Read user data |
| `write:users` | Write user data |

## 🧪 Testing Options

### Option 1: Swagger UI (Recommended)

1. Visit **http://localhost:8000/docs**
2. Click **"Authorize"** button in top-right
3. Choose authentication method:
   - **BearerAuth**: Paste JWT token directly
   - **Auth0Bearer**: OAuth2 Client Credentials Flow (for server-to-server)
   - **Auth0SPA**: OAuth2 Authorization Code + PKCE (for SPAs)
4. **Select scopes** by checking the boxes (e.g., `openid`, `profile`, `email`, `read:users`)
5. **Authorize** and test endpoints interactively

#### For SPAs (Auth0SPA):
- No client secret required
- Uses PKCE for security
- Automatically includes `audience` parameter for JWT tokens
- Fetches user profile data when `openid` scope is selected

#### For Server Apps (Auth0Bearer):
- Requires client ID and client secret
- Machine-to-machine authentication
- Ideal for backend services

### Option 2: Client Example

```bash
# Test public endpoints
python client_example.py --test-public

# Full demo with Auth0 credentials
python client_example.py --with-auth

# Show flow explanation
python client_example.py
```

### Option 3: cURL Commands

```bash
# Public endpoint (no auth)
curl http://localhost:8000/public

# Protected endpoint (requires token)
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/protected

# DPoP authentication
curl -H "Authorization: DPoP YOUR_ACCESS_TOKEN" \
     -H "DPoP: YOUR_DPOP_PROOF" \
     http://localhost:8000/protected/dpop

# Token information
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/token/info
```

## 🔧 Auth0 Setup Guide

### 1. Create Auth0 Account
- Sign up at [auth0.com](https://auth0.com)

### 2. Create API
- Go to **APIs** → **Create API**
- Set **Identifier** (becomes your `AUTH0_AUDIENCE`)
- Choose **RS256** signing algorithm

### 3. Add Scopes
Configure these scopes in your Auth0 API:
- `openid` - Required for user identity and profile data
- `profile` - For user name and picture
- `email` - For user email address
- `read:users` - For scoped endpoint access
- `write:users` - For write operations

### 4. Create Applications

#### For Server-to-Server (Auth0Bearer):
- Go to **Applications** → **Create Application**
- Choose **Machine to Machine**
- Authorize for your API
- Note **Client ID** and **Client Secret**

#### For SPAs (Auth0SPA):
- Go to **Applications** → **Create Application**  
- Choose **Single Page Application**
- Set **Allowed Callback URLs**: `http://localhost:8000/docs/oauth2-redirect`
- Set **Allowed Web Origins**: `http://localhost:8000`
- Note **Client ID** (no client secret for SPAs)

### 5. Environment Variables

```bash
# Required
AUTH0_DOMAIN=your-domain.auth0.com
AUTH0_AUDIENCE=https://your-api.example.com

# Optional (for client testing)
AUTH0_CLIENT_ID=your-machine-to-machine-client-id
AUTH0_CLIENT_SECRET=your-client-secret
```

## 🏗️ Project Structure

```
fastapi-auth0-token-verifier/
├── src/
│   ├── fastapi_auth0_token_verifier/
│   │   ├── __init__.py
│   │   └── auth.py        # Main application with all features
│   └── __init__.py
├── requirements.txt       # Python dependencies  
├── pyproject.toml         # Project configuration
├── .env.example          # Environment template
├── .gitignore            # Git ignore rules
├── LICENSE               # MIT license
└── README.md             # This documentation
```


### Verification Process

When a request arrives with a JWT token, the API automatically verifies:

1. **Signature Validation** - Token signed by Auth0 (RS256)
2. **Expiration Check** - Token hasn't expired (`exp` claim)
3. **Issuer Verification** - Token from correct Auth0 domain (`iss`)
4. **Audience Validation** - Token intended for this API (`aud`)
5. **Not Before Check** - Token is currently valid (`nbf`)
6. **Custom Claims** - Any additional required claims

## 🛡️ Security Features

- **Automatic JWKS Fetching** - Public keys retrieved from Auth0
- **Token Caching** - Efficient verification with intelligent caching
- **Comprehensive Error Handling** - Clear, actionable error messages
- **DPoP Support** - Advanced proof-of-possession security
- **Scope Validation** - Fine-grained permission checking
- **Request Context** - Full request information for verification

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/your-username/fastapi-auth0-token-verifier/issues)
- **Community**: [Auth0 Community](https://community.auth0.com)

---

**Made with ❤️ for the Auth0 developer community**
