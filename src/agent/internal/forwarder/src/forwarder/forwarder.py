import logging
import requests
from requests.auth import HTTPProxyAuth
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import Optional, Dict, Any


logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ForwarderError(Exception):
    """Custom exception for forwarder-related errors."""
    pass


class HTTPForwarder:
    """
    A reusable HTTP forwarder that supports proxy authentication and direct connections.
    """

    def __init__(self, proxy_url: Optional[str] = None, proxy_auth: Optional[Dict[str, str]] = None):
        """
        Initialize the HTTP forwarder.

        :param proxy_url: URL of the proxy server (e.g., "http://proxy.example.com:8080").
        :param proxy_auth: Dictionary containing proxy authentication credentials (e.g., {"username": "user", "password": "pass"}).
        """
        self.proxy_url = proxy_url
        self.proxy_auth = proxy_auth
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """
        Create a requests session with retry logic.

        :return: Configured requests.Session object.
        """
        session = requests.Session()
        retries = Retry(
            total=5,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE"]
        )
        adapter = HTTPAdapter(max_retries=retries)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _get_proxy_settings(self) -> Dict[str, Any]:
        """
        Generate proxy settings based on the provided proxy URL and authentication.

        :return: Dictionary of proxy settings.
        """
        if not self.proxy_url:
            return {}

        proxy_settings = {
            "http": self.proxy_url,
            "https": self.proxy_url,
        }

        if self.proxy_auth:
            username = self.proxy_auth.get("username")
            password = self.proxy_auth.get("password")
            if username and password:
                proxy_settings["auth"] = HTTPProxyAuth(username, password)
            else:
                logger.warning("Proxy authentication credentials are incomplete.")
        return proxy_settings

    def forward_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Forward an HTTP request to the backend API.

        :param method: HTTP method (e.g., "GET", "POST").
        :param url: Target URL for the request.
        :param kwargs: Additional arguments for the request (e.g., headers, data).
        :return: Response object from the backend API.
        :raises ForwarderError: If the request fails after retries.
        """
        try:
            proxy_settings = self._get_proxy_settings()
            logger.info(f"Forwarding {method} request to {url} using proxy: {bool(self.proxy_url)}")

            response = self.session.request(method, url, proxies=proxy_settings, **kwargs)
            response.raise_for_status()  # Raise HTTPError for bad responses (4xx and 5xx)
            return response

        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed: {e}")
            raise ForwarderError(f"Failed to forward request to {url}: {e}")