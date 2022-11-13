import os
import httpx

from aiohttp import BasicAuth


async def login(request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None, ("missing credentials", 401)

    auth = BasicAuth.decode(auth_header=auth_header)

    async with httpx.AsyncClient() as client:
        response = await client.post(
            f'http://{os.getenv("AUTH_SVC_ADDRESS")}/login',
            auth=(auth.login, auth.password),
        )

    if response.status_code != 200:
        return None, (response.text, response.status_code)
    return response.text, None
