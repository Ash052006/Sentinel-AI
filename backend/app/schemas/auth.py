from pydantic import BaseModel, EmailStr, Field


class UserRegister(BaseModel):
    email: EmailStr = Field(
        ...,
        max_length=254,
        description="Account email (RFC 5321 total-length bound).",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password must be between 8 and 128 characters",
    )


class LoginRequest(BaseModel):
    """Structured login credentials carried in the request body.

    Credentials must travel in the JSON body, never in the URL query
    string (query parameters are logged by proxies, ordered intermediate
    systems and browser history; the query-string transport is removed in
    hardening phase H2).
    """

    email: EmailStr = Field(
        ...,
        max_length=254,
        description="The account's email (RFC 5321 total-length bound).",
    )
    password: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="The account's password.",
    )


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    