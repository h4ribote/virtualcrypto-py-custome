from .structs import Currency, Scope, Claim, ClaimStatus, Balance
from .errors import MissingScope, BadRequest, NotFound, Conflict
from typing import Optional, List
import aiohttp
import asyncio
from time import time

VIRTUALCRYPTO_ENDPOINT = "https://vcrypto.sumidora.com"
VIRTUALCRYPTO_API_V1 = VIRTUALCRYPTO_ENDPOINT + "/api/v1"
VIRTUALCRYPTO_API_V2 = VIRTUALCRYPTO_ENDPOINT + "/api/v2"
VIRTUALCRYPTO_TOKEN_ENDPOINT = VIRTUALCRYPTO_ENDPOINT + "/oauth2/token"

class AsyncVirtualCryptoClient:
    def __init__(self, client_id: str, client_secret: str, scopes: List[Scope], version: str = "v2"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.default_version = version
        self.token = None
        self.expires_in = None
        self.token_type = None
        self.when_set_token = None
        self.loop = asyncio.get_running_loop()
        self.session = aiohttp.ClientSession(loop=self.loop)
        self.wait_ready = asyncio.Event(loop=self.loop)

    async def wait_for_ready(self):
        await self.wait_ready.wait()

    async def start(self):
        await self.set_token()
        self.wait_ready.set()

    async def close(self):
        await self.session.close()

    async def set_token(self):
        body = {
            'scope': ' '.join(map(lambda x: x.value, self.scopes)),
            'grant_type': 'client_credentials'
        }
        async with self.session.post(
                VIRTUALCRYPTO_TOKEN_ENDPOINT,
                data=body,
                auth=aiohttp.BasicAuth(self.client_id, self.client_secret)) as response:
            data = await response.json()

        self.token = data['access_token']
        self.expires_in = data['expires_in']
        self.token_type = data['token_type']
        self.when_set_token = int(time())

    async def get_headers(self):
        if (int(time()) - self.when_set_token) >= self.expires_in:
            await self.set_token()
        return {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json"
        }

    async def get(self, path, params, version=None) -> aiohttp.ClientResponse:
        headers = await self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        return await self.session.get(f"{base_url}{path}", params=params, headers=headers)

    async def post(self, path, data, version=None) -> aiohttp.ClientResponse:
        headers = await self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        return await self.session.post(f"{base_url}{path}", json=data, headers=headers)

    async def patch(self, path, data, version=None) -> aiohttp.ClientResponse:
        headers = await self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        return await self.session.patch(f"{base_url}{path}", json=data, headers=headers)

    async def get_currency_by_unit(self, unit: str) -> Optional[Currency]:
        response = await self.get("/currencies", {"unit": unit})
        return Currency.by_json(await response.json())

    async def get_currency_by_guild(self, guild_id: int) -> Optional[Currency]:
        response = await self.get("/currencies", {"guild": str(guild_id)})
        return Currency.by_json(await response.json())

    async def get_currency_by_name(self, name: str) -> Optional[Currency]:
        response = await self.get("/currencies", {"name": name})
        return Currency.by_json(await response.json())

    async def get_currency(self, currency_id: int):
        response = await self.get("/currencies/" + str(currency_id), {})
        return Currency.by_json(await response.json())

    async def create_user_transaction(self, unit: str, receiver_discord_id: int, amount: int) -> None:
        if Scope.Pay not in self.scopes:
            raise MissingScope("vc.pay")

        response = await self.post(
            "/users/@me/transactions",
            {
                "unit": unit,
                "receiver_discord_id": str(receiver_discord_id),
                "amount": str(amount)
            }
        )
        if response.status == 400:
            raise BadRequest((await response.json()).get("error_info"))
        elif response.status == 409:
            raise Conflict((await response.json()).get("error_info"))

    pay = create_user_transaction

    async def create_claim(self, payer_discord_id: int, unit: str, amount: int, metadata: Optional[dict] = None) -> Claim:
        if Scope.Claim not in self.scopes:
            raise MissingScope("vc.claim")

        payload = {
            "payer_discord_id": str(payer_discord_id),
            "unit": unit,
            "amount": str(amount)
        }
        if metadata is not None:
            payload["metadata"] = metadata

        response = await self.post("/users/@me/claims", payload)

        if response.status == 400:
            raise BadRequest((await response.json()).get("error_info"))
        return Claim.by_json(await response.json())


    async def get_claims(self, **kwargs):
        if Scope.Claim not in self.scopes:
            raise MissingScope("vc.claim")

        response = await self.get(
            "/users/@me/claims",
            kwargs
        )
        return list(map(Claim.by_json, await response.json()))

    async def get_claim(self, claim_id: int):
        response = await self.get("/users/@me/claims/" + str(claim_id), {})
        return Claim.by_json(await response.json())

    async def update_claim(self, claim_id: int, status: ClaimStatus, metadata: Optional[dict] = None):
        if status == ClaimStatus.Pending:
            raise ValueError("can't update to pending")

        payload = {"status": status.value}
        if metadata is not None:
            payload["metadata"] = metadata

        response = await self.patch(
            "/users/@me/claims/" + str(claim_id),
            payload
        )

        if response.status == 404:
            raise NotFound((await response.json()).get("error_description"))
        elif response.status == 400:
            raise BadRequest((await response.json()).get("error_info"))
        elif response.status == 409:
            raise Conflict((await response.json()).get("error_info"))

        return Claim.by_json(await response.json())

    async def get_balances(self):
        response = await self.get(
            "/users/@me/balances",
            {},
            version="v1"
        )
        return list(map(Balance.by_json, await response.json()))
