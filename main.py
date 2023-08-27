from typing import Any
import os
import jwt
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import ssl


HANKO_API_URL = os.environ.get("HANKO_API_URL")


def deny():
    return JSONResponse(content={"error": "Unauthorized"}, status_code=401)


def extract_token_from_header(header: str) -> str:
    parts = header.split()
    return parts[1] if len(parts) == 2 and parts[0].lower() == "bearer" else None


app = FastAPI()


@app.middleware("http")
async def auth(request: Request, call_next: Any):
    authorization = request.headers.get("authorization")

    if not authorization:
        return deny()

    token = extract_token_from_header(authorization)

    if not token:
        return deny()

    # Disable SSL certificate verification
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        jwks_client = jwt.PyJWKClient(
            HANKO_API_URL + "/.well-known/jwks.json", ssl_context=ssl_context
        )
        signing_key = jwks_client.get_signing_key_from_jwt(token)
        data = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience="localhost",
        )

        if not data:
            return deny()

        return await call_next(request)

    except (jwt.DecodeError, Exception) as e:
        print(f"Authentication error: {e}")
        return deny()


@app.get("/protected")
async def protected():
    return {"message": "protected message"}
