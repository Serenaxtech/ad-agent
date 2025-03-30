from agent.internal.authenticator.src.authenticator.authenticator import AgentAuthChecker

def check_agent_authentication():
    base_url = "http://localhost:3000" 
    agent_id = "accec0d4-6989-4a75-b911-bb82994fd161"
    agent_token = "3fc5ffd766ffa48155b5d50452a38df688d5e6c4bd8e990a63e136fb3a4bc127"

    proxy_url = None
    proxy_auth = None


    auth_checker = AgentAuthChecker(
        base_url=base_url,
        agent_id=agent_id,
        agent_token=agent_token,
        proxy_url=proxy_url,
        proxy_auth=proxy_auth
    )


    is_authenticated = auth_checker.verify_authentication()

    if is_authenticated:
        print("Agent is authenticated.")
    else:
        print("Agent authentication failed.")

if __name__ == "__main__":
    check_agent_authentication()