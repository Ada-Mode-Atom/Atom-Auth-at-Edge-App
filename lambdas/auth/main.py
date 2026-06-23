import asyncio
import base64
import hashlib
import re
import secrets
import time
from http.cookies import SimpleCookie
from typing import Literal
from urllib.parse import parse_qs, urlencode, urljoin

import aiohttp
import boto3
import requests
from jose import jwk, jwt
from jose.utils import base64url_decode

ssm_client = boto3.client("ssm", region_name="us-east-1")


async def _get_param(name: str) -> str:
    response = await asyncio.to_thread(
        ssm_client.get_parameter,
        Name=name,
        WithDecryption=True,
    )
    return response["Parameter"]["Value"]


PKCE_COOKIE_NAME = "ATOM_PKCE_VERIFIER"


async def get_openid_configuration_url(namespace: str) -> str:
    return await _get_param(f"/{namespace}/auth/config")


async def get_redirect_path(namespace: str) -> str:
    return await _get_param(f"/{namespace}/auth/redirect")


async def get_client_id(namespace: str) -> str:
    return await _get_param(f"/{namespace}/auth/client_id")


async def get_scope(namespace: str) -> list[str]:
    scope = await _get_param(f"/{namespace}/auth/scope")
    return scope.split(sep=" ")


async def get_openid_config(url: str) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:
            resp.raise_for_status()
            return await resp.json()


async def get_jkws(config: dict) -> dict:
    async with aiohttp.ClientSession() as session:
        async with session.get(config["jwks_uri"]) as resp:
            resp.raise_for_status()
            return await resp.json()


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_pkce_pair() -> tuple[str, str]:
    code_verifier = _base64url(secrets.token_bytes(64))
    code_challenge = _base64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    return code_verifier, code_challenge


def request_refresh(client_id: str, refresh_token: str, config: dict, scope: list[str]) -> tuple[str, str, str]:
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "refresh_token": refresh_token,
        "scope": " ".join(scope),
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(
        config["token_endpoint"],
        data=payload,
        headers=headers,
        timeout=10,
    )
    try:
        res.raise_for_status()
    except requests.exceptions.RequestException as e:
        try:
            detail = res.json()
        except Exception:
            detail = res.text

        raise Exception(f"Token endpoint error ({detail}): {e}") from e

    jwt = res.json()
    id_token = jwt.get("id_token", "")
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", refresh_token)

    return id_token, access_token, refresh_token


def request_token(
    code: str, client_id: str, redirect_uri: str, config: dict, scope: list[str], code_verifier: str
) -> tuple[str, str, str]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": code,
        "redirect_uri": redirect_uri,
        "scope": " ".join(scope),
        "code_verifier": code_verifier,
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    res = requests.post(
        config["token_endpoint"],
        data=payload,
        headers=headers,
        timeout=10,
    )
    try:
        res.raise_for_status()
    except requests.exceptions.HTTPError as e:
        raise Exception(f"HTTP error occurred ({res.json()}): {e}")
    except requests.exceptions.RequestException as e:
        raise Exception(f"A request error occurred ({res.json()}): {e}")

    jwt = res.json()

    id_token = jwt.get("id_token", "")
    access_token = jwt["access_token"]
    refresh_token = jwt.get("refresh_token", "")

    return id_token, access_token, refresh_token


def request_signin(client_id: str, state: str, redirect_uri: str, scope: list[str], config: dict) -> dict:
    code_verifier, code_challenge = create_pkce_pair()
    query = urlencode(
        {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(scope),
            "redirect_uri": redirect_uri,
            "state": state,
            "response_mode": "query",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
    )
    response = {
        "status": "307",
        "statusDescription": "Temporary Redirect",
        "headers": {
            "location": [
                {
                    "key": "Location",
                    "value": f"{config['authorization_endpoint']}?{query}",
                },
            ],
            "set-cookie": [
                build_set_cookie_header(
                    PKCE_COOKIE_NAME,
                    code_verifier,
                    max_age=300,
                )
            ],
        },
    }

    return response


def build_set_cookie_header(
    name: str,
    value: str,
    *,
    max_age: int | None = None,
    path: str = "/",
) -> dict:
    cookie = f"{name}={value}; Path={path}; Secure; HttpOnly; SameSite=Lax"

    if max_age is not None:
        cookie += f"; Max-Age={max_age}"

    return {
        "key": "Set-Cookie",
        "value": cookie,
    }


def build_clear_cookie_header(name: str, *, path: str = "/") -> dict:
    return build_set_cookie_header(name, "", max_age=0, path=path)


def set_token_cookies(
    response: dict,
    id_token: str,
    access_token: str,
    refresh_token: str,
    clear_pkce: bool = True,
) -> dict:
    cookie_list = response["headers"].get("set-cookie", [])

    if id_token:
        cookie_list.append(build_set_cookie_header("ATOM_ID_TOKEN", id_token))

    if access_token:
        cookie_list.append(build_set_cookie_header("ATOM_ACCESS_TOKEN", access_token))

    if refresh_token:
        cookie_list.append(build_set_cookie_header("ATOM_REFRESH_TOKEN", refresh_token))

    if clear_pkce:
        cookie_list.append(build_clear_cookie_header(PKCE_COOKIE_NAME))

    response["headers"]["set-cookie"] = cookie_list
    return response


def get_cookie(headers: dict, name: str) -> str:
    for cookie in headers.get("cookie", []):
        for part in cookie["value"].split(";"):
            part = part.strip()

            if "=" not in part:
                continue

            cookie_name, cookie_value = part.split("=", 1)

            if cookie_name == name:
                return cookie_value

    return ""


def get_token_cookies(headers: dict) -> tuple[str, str, str]:
    raw_cookie = "; ".join(cookie["value"] for cookie in headers.get("cookie", []))

    parsed = SimpleCookie()
    parsed.load(raw_cookie)

    return (
        parsed["ATOM_ID_TOKEN"].value if "ATOM_ID_TOKEN" in parsed else "",
        parsed["ATOM_ACCESS_TOKEN"].value if "ATOM_ACCESS_TOKEN" in parsed else "",
        parsed["ATOM_REFRESH_TOKEN"].value if "ATOM_REFRESH_TOKEN" in parsed else "",
    )


def redirect_with_token_cookies(
    location: str,
    id_token: str,
    access_token: str,
    refresh_token: str,
    clear_pkce: bool = True,
) -> dict:
    response = {
        "status": "307",
        "statusDescription": "Temporary Redirect",
        "headers": {
            "location": [
                {
                    "key": "Location",
                    "value": location,
                }
            ],
            "set-cookie": [],
        },
    }

    return set_token_cookies(
        response,
        id_token=id_token,
        access_token=access_token,
        refresh_token=refresh_token,
        clear_pkce=clear_pkce,
    )


def verify_token(access_token: str, jwks: dict) -> Literal["REFRESH", "SIGNIN", "CONTINUE"]:
    if not access_token:
        return "SIGNIN"

    jwtHeaders = jwt.get_unverified_headers(access_token)
    kid = jwtHeaders["kid"]

    keys = jwks["keys"]

    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]["kid"]:
            key_index = i
            break
    if key_index == -1:
        raise Exception("Public key not found in jwks.json")

    publicKey = jwk.construct(keys[key_index])

    message, encoded_signature = str(access_token).rsplit(".", 1)
    decoded_signature = base64url_decode(encoded_signature.encode("utf-8"))
    if not publicKey.verify(message.encode("utf8"), decoded_signature):
        raise Exception("Signature verification failed")

    claims = jwt.get_unverified_claims(access_token)
    if time.time() > claims["exp"]:
        return "REFRESH"

    return "CONTINUE"


def _build_redirect_uri(request: dict, redirect_path: str) -> str:
    host = request["headers"]["host"][0]["value"]
    return urljoin(f"https://{host}", redirect_path)


def _build_uri(request: dict) -> str:
    host = request["headers"]["host"][0]["value"]
    uri = request["uri"]
    query = request.get("querystring", "")

    url = f"https://{host}{uri}?{query}" if query else f"https://{host}{uri}"

    return url


def _extract_namespace(fn_name) -> str:
    # Expecting format like "auth-handler-prod"
    match = re.search(r"auth-(?:handler|callback)-([a-zA-Z0-9_-]+)", fn_name)
    return match.group(1) if match else "default"


async def _auth_handler(event: dict, context) -> dict:
    namespace = _extract_namespace(context.function_name)

    __OPENID_CONFIGURATION_URL__ = await get_openid_configuration_url(namespace=namespace)
    __CONFIG__ = await get_openid_config(url=__OPENID_CONFIGURATION_URL__)
    __JWKS__ = await get_jkws(config=__CONFIG__)
    __SCOPE__ = await get_scope(namespace=namespace)

    request = event["Records"][0]["cf"]["request"]
    headers = request["headers"]

    _, access_token, refresh_token = get_token_cookies(headers)

    try:
        action = verify_token(access_token, jwks=__JWKS__)
    except Exception:
        return {
            "status": "403",
            "statusDescription": "Forbidden",
            "body": "Invalid token",
        }

    if action == "CONTINUE":
        return request

    __CLIENT_ID__ = await get_client_id(namespace=namespace)
    __REDIRECT_PATH__ = await get_redirect_path(namespace=namespace)

    if action == "REFRESH":
        try:
            id_token, access_token, refresh_token = request_refresh(
                client_id=__CLIENT_ID__, refresh_token=refresh_token, config=__CONFIG__, scope=__SCOPE__
            )
        except Exception as _:
            return request_signin(
                client_id=__CLIENT_ID__,
                state=_build_uri(request),
                redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
                config=__CONFIG__,
                scope=__SCOPE__,
            )
        else:
            return redirect_with_token_cookies(
                location=_build_uri(request),
                id_token=id_token,
                access_token=access_token,
                refresh_token=refresh_token,
                clear_pkce=False,
            )

    else:
        return request_signin(
            client_id=__CLIENT_ID__,
            state=_build_uri(request),
            redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
            config=__CONFIG__,
            scope=__SCOPE__,
        )


def auth_handler(event: dict, context) -> dict:
    return asyncio.run(_auth_handler(event, context))


async def _callback_handler(event: dict, context) -> dict:
    namespace = _extract_namespace(context.function_name)

    __OPENID_CONFIGURATION_URL__ = await get_openid_configuration_url(namespace=namespace)
    __CONFIG__ = await get_openid_config(url=__OPENID_CONFIGURATION_URL__)
    __CLIENT_ID__ = await get_client_id(namespace=namespace)
    __REDIRECT_PATH__ = await get_redirect_path(namespace=namespace)
    __SCOPE__ = await get_scope(namespace=namespace)

    request = event["Records"][0]["cf"]["request"]
    headers = request["headers"]
    query_params = parse_qs(request.get("querystring", ""))
    code = query_params.get("code", [""])[0]
    state = query_params.get("state", ["/"])[0]

    if "error" in query_params:
        return {
            "status": "403",
            "statusDescription": "Forbidden",
            "body": query_params.get("error_description", ["Authentication failed"])[0],
        }

    if not code:
        return {
            "status": "400",
            "statusDescription": "Bad Request",
            "body": "Missing authorization code",
        }

    code_verifier = get_cookie(headers, PKCE_COOKIE_NAME)

    if not code_verifier:
        return {
            "status": "400",
            "statusDescription": "Bad Request",
            "body": "Missing PKCE verifier cookie",
        }

    id_token, access_token, refresh_token = request_token(
        code=code,
        client_id=__CLIENT_ID__,
        redirect_uri=_build_redirect_uri(request, __REDIRECT_PATH__),
        config=__CONFIG__,
        scope=__SCOPE__,
        code_verifier=code_verifier,
    )

    return redirect_with_token_cookies(
        location=state or "/",
        id_token=id_token,
        access_token=access_token,
        refresh_token=refresh_token,
        clear_pkce=True,
    )


def callback_handler(event: dict, context) -> dict:
    return asyncio.run(_callback_handler(event, context))
