from requests.auth import HTTPBasicAuth
import requests
from .structs import Currency, Scope, Claim, ClaimStatus, Balance
from .errors import MissingScope, BadRequest, NotFound, Conflict
from typing import Optional, List
import datetime
VIRTUALCRYPTO_ENDPOINT = "https://vcrypto.sumidora.com"
VIRTUALCRYPTO_API_V1 = VIRTUALCRYPTO_ENDPOINT + "/api/v1"
VIRTUALCRYPTO_API_V2 = VIRTUALCRYPTO_ENDPOINT + "/api/v2"
VIRTUALCRYPTO_TOKEN_ENDPOINT = VIRTUALCRYPTO_ENDPOINT + "/oauth2/token"


class VirtualCryptoClient:
    def __init__(self, client_id, client_secret, scopes, version="v2"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self.default_version = version
        self.token = None
        self.expires_in = None
        self.token_type = None
        self.when_set_token = None
        self.set_token()

    def set_token(self):
        body = {
            'scope': ' '.join(map(lambda x: x.value, self.scopes)),
            'grant_type': 'client_credentials'
        }
        data = requests.post(
            VIRTUALCRYPTO_TOKEN_ENDPOINT,
            data=body,
            auth=HTTPBasicAuth(self.client_id, self.client_secret)
        ).json()
        self.token = data['access_token']
        self.expires_in = data['expires_in']
        self.token_type = data['token_type']
        self.when_set_token = datetime.datetime.utcnow()

    def get_headers(self):
        if (datetime.datetime.utcnow() - self.when_set_token).seconds >= self.expires_in:
            self.set_token()
        return {
            "Authorization": "Bearer " + self.token,
            "Content-Type": "application/json"
        }

    def get(self, path, params, version=None) -> requests.Response:
        headers = self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        response = requests.get(
            f"{base_url}{path}",
            params=params,
            headers=headers
        )
        return response

    def post(self, path, data, version=None) -> requests.Response:
        headers = self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        response = requests.post(
            f"{base_url}{path}",
            headers=headers,
            json=data
        )
        return response

    def patch(self, path, data, version=None) -> requests.Response:
        headers = self.get_headers()
        request_version = version if version is not None else self.default_version
        base_url = VIRTUALCRYPTO_API_V2 if request_version == "v2" else VIRTUALCRYPTO_API_V1
        response = requests.patch(
            f"{base_url}{path}",
            json=data,
            headers=headers
        )
        return response

    def get_currency_by_unit(self, unit: str) -> Optional[Currency]:
        return Currency.by_json(self.get("/currencies", {"unit": unit}).json())

    def get_currency_by_guild(self, guild_id: int) -> Optional[Currency]:
        return Currency.by_json(self.get("/currencies", {"guild": str(guild_id)}).json())

    def get_currency_by_name(self, name: str) -> Optional[Currency]:
        return Currency.by_json(self.get("/currencies", {"name": name}).json())

    def get_currency(self, currency_id: int):
        return Currency.by_json(self.get("/currencies/" + str(currency_id), {}).json())

    def create_user_transaction(self, unit: str, receiver_discord_id: int, amount: int) -> None:
        if Scope.Pay not in self.scopes:
            raise MissingScope("vc.pay")

        response = self.post(
            "/users/@me/transactions",
            {
                "unit": unit,
                "receiver_discord_id": str(receiver_discord_id),
                "amount": str(amount)
            }
        )
        if response.status_code == 400:
            raise BadRequest(response.json().get("error_info"))
        elif response.status_code == 409:
            raise Conflict(response.json().get("error_info"))


    pay = create_user_transaction

    def create_claim(self, payer_discord_id: int, unit: str, amount: int, metadata: Optional[dict] = None) -> Claim:
        if Scope.Claim not in self.scopes:
            raise MissingScope("vc.claim")

        payload = {
            "payer_discord_id": str(payer_discord_id),
            "unit": unit,
            "amount": str(amount)
        }
        if metadata is not None:
            payload["metadata"] = metadata

        response = self.post("/users/@me/claims", payload)

        if response.status_code == 400:
            raise BadRequest(response.json().get("error_info"))

        return Claim.by_json(response.json())

    def get_claims(self, **kwargs):
        if Scope.Claim not in self.scopes:
            raise MissingScope("vc.claim")

        response = self.get(
            "/users/@me/claims",
            kwargs
        )
        return list(map(Claim.by_json, response.json()))

    def get_claim(self, claim_id: int):
        data = self.get("/users/@me/claims/" + str(claim_id), {}).json()
        return Claim.by_json(data)

    def update_claim(self, claim_id: int, status: ClaimStatus, metadata: Optional[dict] = None):
        if status == ClaimStatus.Pending:
            raise ValueError("can't update to pending")

        payload = {"status": status.value}
        if metadata is not None:
            payload["metadata"] = metadata

        response = self.patch(
            "/users/@me/claims/" + str(claim_id),
            payload
        )

        if response.status_code == 404:
            raise NotFound(response.json().get("error_description"))
        elif response.status_code == 400:
            raise BadRequest(response.json().get("error_info"))
        elif response.status_code == 409:
            raise Conflict(response.json().get("error_info"))

        return Claim.by_json(response.json())

    def get_balances(self):
        response = self.get(
            "/users/@me/balances",
            {},
            version="v1"
        )
        return list(map(Balance.by_json, response.json()))
