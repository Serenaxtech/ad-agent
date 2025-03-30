import logging
from forwarder import HTTPForwarder, ForwarderError

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

class AgentAuthChecker:
    """
    A utility class to verify agent authentication using the HTTPForwarder.
    """

    def __init__(self, base_url: str, agent_id: str, agent_token: str, proxy_url: str = None, proxy_auth: dict = None):
        """
        Initialize the AgentAuthChecker.

        :param base_url: Base URL of the backend API (e.g., "http://localhost:3000").
        :param agent_id: The unique ID of the agent.
        :param agent_token: The authentication token of the agent.
        :param proxy_url: Optional proxy URL for the HTTPForwarder.
        :param proxy_auth: Optional proxy authentication credentials for the HTTPForwarder.
        """
        self.base_url = base_url
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.forwarder = HTTPForwarder(proxy_url=proxy_url, proxy_auth=proxy_auth)

    def verify_authentication(self) -> bool:
        """
        Verify if the agent is authenticated by sending a GET request to the /api/v1/agent endpoint.

        :return: True if the agent is authenticated, False otherwise.
        """
        url = f"{self.base_url}/api/v1/agent"
        headers = {
            "x-agent-token": self.agent_token,
            "x-agent-id": self.agent_id,
        }

        try:
            logger.info(f"Verifying agent authentication for agent ID: {self.agent_id}")
            response = self.forwarder.forward_request("GET", url, headers=headers)

            # Check if the response indicates success (e.g., status code 200)
            if response.status_code == 200:
                logger.info("Agent authentication verified successfully.")
                return True
            else:
                logger.warning(f"Agent authentication failed with status code: {response.status_code}")
                return False

        except ForwarderError as e:
            logger.error(f"Error verifying agent authentication: {e}")
            return False