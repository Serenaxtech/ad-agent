import json
from forwarder import HTTPForwarder, ForwarderError 
# Example proxy settings (optional)
proxy_url = "http://localhost:8080"  # Replace with your proxy URL or set to None if no proxy is needed
proxy_auth = {"username": "", "password": ""}  # Replace with your proxy credentials or set to None

# proxy_url = None
# proxy_auth = None 

# Initialize the HTTPForwarder
forwarder = HTTPForwarder(proxy_url=proxy_url, proxy_auth=proxy_auth)

# Define the API endpoint and payload
url = "http://localhost:3000/api/v1/scan"  # Ensure the URL includes the protocol (http:// or https://)
payload = json.dumps({
    "scan_name": "Test from the forwarder",
    "scan_result": "{kerberos: kerberoastable}",
    "agent_id": "a58c779b-cdad-46ab-8e97-514ee60d97ac"
})
headers = {
    'Content-Type': 'application/json'
}

try:
    # Forward the POST request using the HTTPForwarder
    response = forwarder.forward_request("POST", url, headers=headers, data=payload)

    # Print the response
    print("Response Status Code:", response.status_code)
    print("Response Body:", response.text)

except ForwarderError as e:
    # Handle any errors raised by the forwarder
    print("Error:", e)