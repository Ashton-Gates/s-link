[S-LINK
A custom proxy server built in Python to intercept, inspect, and modify HTTP requests and responses. The server also includes features like MAC address spoofing, NAT translation, and custom encryption.

Features
Proxy Server: Listens on localhost:8080 and forwards HTTP requests to their intended destinations.
MAC Address Spoofing: Allows changing the MAC address of a given network interface.
NAT Translation: Translates source IP addresses to a random IP in the 10.x.x.x range.
Custom Encryption: Provides a framework for encrypting and decrypting data using AES in ECB mode.
Dependencies
scapy: For packet manipulation and crafting.
http.server: For handling HTTP requests.
http.client: For forwarding HTTP requests.
urllib.parse: For parsing URLs.
subprocess: For executing system commands.
Crypto.Cipher: For AES encryption and decryption.
impacket: For packet decoding (Note: Ensure the correct version is installed).
Setup & Installation
Clone the repository:

bash
Copy code
git clone [your-repo-link]
cd Proxy_server
Create a virtual environment and activate it:

bash
Copy code
python -m venv venv_name
source venv_name/bin/activate  # On Windows use `venv_name\Scripts\activate`
Install the required packages:

bash
Copy code
pip install -r requirements.txt
Run the proxy server:

bash
Copy code
python main.py
Usage
Once the proxy server is running, configure your web browser or any other application to use the proxy server at localhost:8080. Any HTTP requests made through this proxy will be intercepted, and you can modify or inspect them as needed.

Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

License
MIT

](https://chat.openai.com/?model=gpt-4-plugins#:~:text=your%20Proxy_server%20application%3A-,Proxy%20Server,MIT,-You%20can%20save)https://chat.openai.com/?model=gpt-4-plugins#:~:text=your%20Proxy_server%20application%3A-,Proxy%20Server,MIT,-You%20can%20save
