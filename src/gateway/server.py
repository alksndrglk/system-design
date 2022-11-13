import os
import json

from aiohhtp import web, BasicAuth
from aiohttp_jwt import JWTMiddleware, login_required
from aio_pika import connect, Message, ExchangeType
from motor.motor_asyncio import AsyncIOMotorClient

from auth import validate
from auth_svc import access
from storage import util


RABBITMQ_URL = os.getenv("RABBITMQ_URL")
MONGO_URL = "mongodb://host.minikube.internal:27017/files"  # os.getenv("MONGO_URL")


def get_client():
    return AsyncIOMotorClient(MONGO_URL)


async def create_connection():
    return await connect(url=RABBITMQ_URL)


async def init_rabbit():
    connection = await create_connection()
    channel = await connection.channel()


async def login_handler(request: web.Request):
    token, err = await access.login(request)

    if err:
        return err
    return token

app = web.Application()
app.router.add_post("/login", login_handler)

if __name__ == "__main__":
    web.run_app(app, host="0.0.0.0", port=9000)
