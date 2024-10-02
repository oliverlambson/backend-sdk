"""
Mechanisms for authentication and authorization for Superset instances.
"""

from typing import Dict, Optional

from bs4 import BeautifulSoup
from yarl import URL

from preset_cli.auth.main import Auth
from preset_cli.auth.token import TokenAuth


class UsernamePasswordAuth(Auth):  # pylint: disable=too-few-public-methods
    """
    Auth to Superset via username/password.
    """

    def __init__(self, baseurl: URL, username: str, password: Optional[str] = None):
        super().__init__()

        self.csrf_token: Optional[str] = None
        self.baseurl = baseurl
        self.username = username
        self.password = password
        self.auth()

    def get_headers(self) -> Dict[str, str]:
        return {"X-CSRFToken": self.csrf_token} if self.csrf_token else {}

    def auth(self) -> None:
        """
        Login to get CSRF token and JWT.
        """

        # TODO: work-in-progress, not working atm...
        payload = {
            "username": self.username,
            "password": self.password,
            "provider": "db",
            "refresh": False,
        }
        response = self.session.post(
            self.baseurl / "api/v1/security/login",
            json=payload,
        )
        data = response.json()
        access_token = data["access_token"]
        self.token = access_token

        response = self.session.get(
            self.baseurl / "api/v1/security/csrf_token/",
            headers=self.get_headers(),
        )
        data = response.json()
        result = data["result"]
        csrf_token = result
        self.session.headers["X-CSRFToken"] = csrf_token
        self.csrf_token = csrf_token


class SupersetJWTAuth(TokenAuth):  # pylint: disable=abstract-method
    """
    Auth to Superset via JWT token.
    """

    def __init__(self, token: str, baseurl: URL):
        super().__init__(token)
        self.baseurl = baseurl

    def get_csrf_token(self, jwt: str) -> str:
        """
        Get a CSRF token.
        """
        response = self.session.get(
            self.baseurl / "api/v1/security/csrf_token/",  # type: ignore
            headers={"Authorization": f"Bearer {jwt}"},
        )
        response.raise_for_status()
        payload = response.json()
        return payload["result"]

    def get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "X-CSRFToken": self.get_csrf_token(self.token),
        }
