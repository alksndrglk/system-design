import jwt
import os
import datetime
from hashlib import sha256
from functools import partial

from aiohttp.web_exceptions import HTTPUnauthorized, HTTPForbidden
from aiohttp import web, BasicAuth
from aiohttp.web_app import Application

from asyncpgsa import PG
from aiohttp_jwt import JWTMiddleware, login_required

JWT_SECRET = os.getenv("JWT_SECRET")  # "secret"
JWT_ALG = os.getenv("JWT_ALG")  # "HS256"
DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")

jwt_middleware = JWTMiddleware(JWT_SECRET, request_property="token", algorithms=JWT_ALG)

DEFAULT_PG_URL = "postgresql://{}:{}@{}:{}/{}"
POOL_SIZE = 10


async def setup_pg(app: Application) -> PG:
    app["pg"] = PG()
    await app["pg"].init(
        DEFAULT_PG_URL.format(DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME),
        min_size=POOL_SIZE,
        max_size=POOL_SIZE,
    )
    await app["pg"].fetchval("SELECT 1")

    try:
        yield
    finally:
        await app["pg"].pool.close()


def is_password_valid(query_password, password: str):
    return query_password == sha256(password.encode()).hexdigest()


def create_jwt(email, secret, authz):
    return jwt.encode(
        {
            "email": email,
            "exp": datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(days=1),
            "iat": datetime.datetime.utcnow(),
            "admin": authz,
        },
        secret,
        algorithm=JWT_ALG,
    )


async def login_handler(request: web.Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPUnauthorized(reason="missing credentials")

    auth = BasicAuth.decode(auth_header=auth_header)
    if not auth or not auth.login or not auth.password:
        raise HTTPForbidden

    email, password = auth.login, auth.password
    query = "SELECT email, password FROM auth_users WHERE email = %s", (email,)
    res = await request.app["pg"].fetchrow(query)
    if not res:
        raise HTTPForbidden(reason="invalid email")
    query_email = res["email"]
    query_password = res["password"]

    if not is_password_valid(query_password, password):
        raise HTTPForbidden(reason="invalid password")

    return web.json_response(create_jwt(query_email, JWT_SECRET, True))


@login_required
async def validate_handler(request):
    return web.json_response({"token": request["token"]})


app = web.Application(middlewares=[jwt_middleware])
app.cleanup_ctx.append(setup_pg)

app.router.add_post("/login", login_handler)
app.router.add_post("/validate", validate_handler)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=9000)
