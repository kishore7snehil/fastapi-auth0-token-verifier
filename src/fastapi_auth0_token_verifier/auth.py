"""
FastAPI Auth0 Token Verifier
A comprehensive demonstration of JWT and DPoP token verification using Auth0 with FastAPI.
"""

# Standard library imports
import base64
import os
import urllib.parse
from typing import Any, Dict, Optional

# Third-party imports
import httpx
import uvicorn
from auth0_api_python import ApiClient, ApiClientOptions
from auth0_api_python.errors import BaseAuthError
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Security
from fastapi.openapi.models import OAuthFlowClientCredentials, OAuthFlows
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2
from pydantic import BaseModel

# Load environment variables from .env file
load_dotenv()


# =============================================================================
# MODELS
# =============================================================================

class UserProfile(BaseModel):
    """User profile information extracted from token claims."""
    sub: str
    email: Optional[str] = None
    name: Optional[str] = None
    picture: Optional[str] = None
    custom_claims: Optional[Dict[str, Any]] = None


class ProtectedResource(BaseModel):
    """Response model for protected endpoints."""
    message: str
    user: UserProfile
    token_claims: Dict[str, Any]


# =============================================================================
# CONFIGURATION
# =============================================================================

# Auth0 Configuration
AUTH0_DOMAIN = os.getenv("AUTH0_DOMAIN", "dev-cz7vb2ggqqahhzfw.us.auth0.com")  
AUTH0_AUDIENCE = os.getenv("AUTH0_AUDIENCE", "https://fastapi-auth0-verifier")

# Available scopes for SPA - users can select these via Swagger UI checkboxes
SPA_SCOPES = {
    "openid": "OpenID Connect",
    "profile": "User profile information",
    "email": "User email address",
    "read:users": "Read user data",
    "write:users": "Write user data",
    # "read:posts": "Read posts",
    # "write:posts": "Write posts",
    # "admin": "Admin access",
    # "delete:users": "Delete users"
}

# Client Credentials scopes - these are configured in Auth0 dashboard, not user-selectable
CLIENT_CREDENTIALS_SCOPES = {
    "read:users": "Read user data",
    "write:users": "Write user data"
}

# Initialize Auth0 API Client
api_client = ApiClient(
    ApiClientOptions(
        domain=AUTH0_DOMAIN,
        audience=AUTH0_AUDIENCE,
        dpop_enabled=True,
        dpop_required=False,
    )
)


# =============================================================================
# SECURITY SCHEMES
# =============================================================================

class Auth0ClientCredentials(OAuth2):
    """Custom Auth0 OAuth2 Client Credentials scheme."""
    
    def __init__(
        self,
        token_url: str,
        audience: str,
        scopes: Dict[str, str] = None,
        scheme_name: Optional[str] = None,
        auto_error: bool = True,
    ):
        if scopes is None:
            scopes = {}
        token_url_with_audience = f"{token_url}?audience={urllib.parse.quote(audience)}"
        flows = OAuthFlows(
            clientCredentials=OAuthFlowClientCredentials(
                tokenUrl=token_url_with_audience, scopes=scopes
            )
        )
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        return None


class Auth0HTTPBearer(HTTPBearer):
    """Custom Auth0 security scheme for Swagger."""
    
    def __init__(self, auto_error: bool = True):
        super().__init__(auto_error=auto_error)
        self.scheme_name = "BearerAuth"


# Initialize security schemes
security = Auth0HTTPBearer()
auth0_oauth2 = Auth0ClientCredentials(
    token_url=f"https://{AUTH0_DOMAIN}/oauth/token",
    audience=AUTH0_AUDIENCE,
    scopes=CLIENT_CREDENTIALS_SCOPES,
    scheme_name="Auth0Bearer",
)

# SPA OAuth2 scheme (Authorization Code + PKCE)
class Auth0SPA(OAuth2):
    """Auth0 OAuth2 scheme for SPAs using Authorization Code + PKCE flow."""
    
    def __init__(self):
        # Include audience parameter in authorization URL to get JWT access tokens
        authorization_url_qs = urllib.parse.urlencode({'audience': AUTH0_AUDIENCE})
        authorization_url = f"https://{AUTH0_DOMAIN}/authorize?{authorization_url_qs}"
        
        flows = OAuthFlows(
            authorizationCode={
                "authorizationUrl": authorization_url,
                "tokenUrl": f"https://{AUTH0_DOMAIN}/oauth/token",
                "scopes": SPA_SCOPES
            }
        )
        super().__init__(flows=flows, scheme_name="Auth0SPA")

    async def __call__(self, request: Request):
        return None

auth0_spa = Auth0SPA()


# =============================================================================
# AUTHENTICATION LOGIC
# =============================================================================

async def get_user_info_from_auth0(access_token: str) -> Dict[str, Any]:
    """Get user profile info from Auth0's /userinfo endpoint."""
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://{AUTH0_DOMAIN}/userinfo",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            if response.status_code == 200:
                return response.json()
            return {}
    except Exception:
        return {}


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(security), 
    request: Request = None
) -> Dict[str, Any]:
    """Verify JWT token using Auth0 API Python SDK."""
    try:
        if request and request.headers.get("dpop"):
            result = await api_client.verify_request(
                headers=dict(request.headers), 
                http_method=request.method, 
                http_url=str(request.url)
            )
            return result
        else:
            # Check if token is JWE (5 segments) vs JWT (3 segments)
            token = credentials.credentials
            segments = token.split('.')
            
            if len(segments) == 5:
                # This is a JWE token - Auth0 is returning encrypted tokens
                raise HTTPException(
                    status_code=401,
                    detail="JWE tokens are not supported. Please configure Auth0 to return JWT tokens instead of encrypted JWE tokens. Check your Auth0 application settings.",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            elif len(segments) != 3:
                raise HTTPException(
                    status_code=401,
                    detail=f"Invalid token format: expected 3 segments for JWT, got {len(segments)}",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            token_data = await api_client.verify_access_token(
                access_token=credentials.credentials
            )
            
            # Enrich with user profile data from /userinfo endpoint
            if "openid" in token_data.get("scope", ""):
                user_info = await get_user_info_from_auth0(credentials.credentials)
                token_data.update(user_info)
            
            return token_data
    except BaseAuthError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "Bearer"},
        ) from e


def verify_scope(required_scope: str):
    """Dependency function to verify specific scope requirements."""
    async def scope_checker(
        token_data: Dict[str, Any] = Security(verify_token)
    ) -> Dict[str, Any]:
        # Extract scopes from token
        scopes = token_data.get("scope", "").split()
        
        if required_scope not in scopes:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required scope: '{required_scope}'",
                headers={"WWW-Authenticate": f"Bearer scope=\"{required_scope}\""},
            )
        
        return token_data
    
    return scope_checker


async def verify_dpop_token(request: Request) -> Dict[str, Any]:
    """Verify DPoP token specifically."""
    try:
        result = await api_client.verify_request(
            headers=dict(request.headers), 
            http_method=request.method, 
            http_url=str(request.url)
        )
        return result
    except BaseAuthError as e:
        raise HTTPException(
            status_code=401,
            detail=f"DPoP authentication failed: {str(e)}",
            headers={"WWW-Authenticate": "DPoP"},
        ) from e


async def oauth_token_proxy(request: Request):
    """Proxy endpoint for OAuth2 token requests that adds audience parameter."""
    form_data = await request.form()
    auth_header = request.headers.get("authorization", "")
    client_id = None
    client_secret = None

    if auth_header.startswith("Basic "):
        encoded_credentials = auth_header[6:]
        try:
            decoded_bytes = base64.b64decode(encoded_credentials)
            decoded_str = decoded_bytes.decode("utf-8")
            client_id, client_secret = decoded_str.split(":", 1)
        except (ValueError, UnicodeDecodeError):
            client_id = None
            client_secret = None

    token_data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": form_data.get("grant_type"),
        "audience": AUTH0_AUDIENCE,
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            json=token_data,
            headers={"Content-Type": "application/json"},
        )

    # Handle empty or invalid JSON responses
    try:
        response_data = response.json() if response.content else {}
    except Exception:
        # If JSON parsing fails, return error response
        response_data = {
            "error": "invalid_response",
            "error_description": "Auth0 returned an invalid or empty response"
        }
        
    return JSONResponse(content=response_data, status_code=response.status_code)


# =============================================================================
# FASTAPI APP
# =============================================================================

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="FastAPI Auth0 Token Verifier",
        description="""
        ## JWT and DPoP Token Verification Demo

        This API demonstrates comprehensive token verification using Auth0's Python SDK.

        ### Supported Authentication Schemes:
        * **Bearer Token**: Standard OAuth 2.0 JWT tokens (RS256)
        * **DPoP**: Enhanced security with Demonstrating Proof-of-Possession (ES256)

        ### Features Demonstrated:
        * JWT access token verification and validation
        * Claims extraction and validation
        * DPoP proof-of-possession verification
        * Scope-based authorization
        * Comprehensive error handling
        * Interactive Swagger documentation
        """,
        version="1.0.0",
        contact={
            "name": "Auth0 Community",
            "url": "https://community.auth0.com",
        },
        license_info={
            "name": "MIT",
            "url": "https://opensource.org/licenses/MIT",
        },
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # Custom OpenAPI schema
    def custom_openapi():
        if app.openapi_schema:
            return app.openapi_schema

        openapi_schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )

        openapi_schema["components"]["securitySchemes"] = {
            "Auth0Bearer": {
                "type": "oauth2",
                "description": "Auth0 OAuth2 with Bearer tokens (Client Credentials Flow) - Scopes pre-configured in Auth0 dashboard",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "/oauth/token",
                        "scopes": CLIENT_CREDENTIALS_SCOPES,
                    }
                },
            },
            "Auth0SPA": {
                "type": "oauth2",
                "description": "Auth0 OAuth2 for SPAs (Authorization Code + PKCE Flow)",
                "flows": {
                    "authorizationCode": {
                        "authorizationUrl": f"https://{AUTH0_DOMAIN}/authorize?audience={urllib.parse.quote(AUTH0_AUDIENCE)}",
                        "tokenUrl": f"https://{AUTH0_DOMAIN}/oauth/token",
                        "scopes": SPA_SCOPES,
                    }
                },
            },
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT Bearer token authentication",
            },
        }

        app.openapi_schema = openapi_schema
        return app.openapi_schema

    app.openapi = custom_openapi
    return app


# Create the app instance
app = create_app()


# =============================================================================
# ROUTES
# =============================================================================

@app.post("/oauth/token", include_in_schema=False)
async def oauth_proxy(request: Request):
    return await oauth_token_proxy(request)


@app.get("/")
async def root():
    return {
        "message": "FastAPI Auth0 Token Verifier Demo",
        "version": "1.0.0",
        "documentation": "/docs",
        "auth0_domain": AUTH0_DOMAIN,
        "audience": AUTH0_AUDIENCE,
        "supported_schemes": ["Bearer", "DPoP"],
    }


@app.get("/public", tags=["Public"])
async def public_endpoint():
    return {
        "message": "This is a public endpoint accessible without authentication",
        "authenticated": False,
        "data": "Public information available to everyone",
    }


@app.get("/protected", response_model=ProtectedResource, tags=["Protected"])
async def protected_endpoint(
    token_data: Dict[str, Any] = Security(verify_token),
    _oauth2_token: Optional[str] = Security(auth0_oauth2),
    _spa_token: Optional[str] = Security(auth0_spa)
):
    user_profile = UserProfile(
        sub=token_data.get("sub", ""),
        email=token_data.get("email"),
        name=token_data.get("nickname"),
        picture=token_data.get("picture"),
        custom_claims={
            k: v for k, v in token_data.items()
            if k not in ["sub", "email", "name", "picture", "iss", "aud", "exp", "iat"]
        },
    )
    return ProtectedResource(
        message="Successfully accessed protected resource with valid token",
        user=user_profile,
        token_claims=token_data,
    )


@app.get("/protected/dpop", response_model=ProtectedResource, tags=["DPoP"])
async def dpop_protected_endpoint(
    request: Request, 
    token_data: Dict[str, Any] = Security(verify_dpop_token)
):
    user_profile = UserProfile(
        sub=token_data.get("sub", ""),
        email=token_data.get("email"),
        name=token_data.get("name"),
        picture=token_data.get("picture"),
        custom_claims={
            k: v for k, v in token_data.items()
            if k not in ["sub", "email", "name", "picture", "iss", "aud", "exp", "iat"]
        },
    )
    return ProtectedResource(
        message="Successfully accessed DPoP protected resource with proof-of-possession",
        user=user_profile,
        token_claims=token_data,
    )


@app.get("/protected-with-scope", tags=["Scoped"], summary="Protected endpoint with read:users scope")
async def protected_with_scope_endpoint(
    token_data: Dict[str, Any] = Security(verify_scope("read:users")),
    _oauth2_token: Optional[str] = Security(auth0_oauth2, scopes=["read:users"]),
    _spa_token: Optional[str] = Security(auth0_spa, scopes=["read:users"])
):
    """Protected endpoint requiring 'read:users' scope."""
    user_profile = UserProfile(
        sub=token_data.get("sub", ""),
        email=token_data.get("email"),
        name=token_data.get("name"),
        picture=token_data.get("picture"),
        custom_claims={
            k: v for k, v in token_data.items()
            if k not in ["sub", "email", "name", "picture", "iss", "aud", "exp", "iat"]
        },
    )
    
    return {
        "message": "This endpoint requires 'read:users' scope",
        "required_scope": "read:users",
        "user": user_profile,
        "permissions": token_data.get("scope", "").split(),
        "user_id": token_data.get("sub"),
        "email": token_data.get("email")
    }



@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "fastapi-auth0-token-verifier",
        "version": "1.0.0",
        "auth0_domain": AUTH0_DOMAIN,
        "audience": AUTH0_AUDIENCE,
    }


if __name__ == "__main__":
    uvicorn.run("auth:app", host="localhost", port=8000, reload=True, log_level="info")
