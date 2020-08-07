# vultr-firewall
Automate the content of a Vultr firewall group using Python.

# Setup
This script uses `pipenv` to manage dependencies and environment variables, as such setup is as simple as.

1. Install `python3`, `python3-pip`.
2. Using `python3-pip` install `pipenv`.
3. Access your Vultr account and generate and [API key](https://my.vultr.com/settings/#settingsapi).
4. Copy `.env.example` to `.env`.
5. Populate the `.env` file as required, for example:
   ```
   VULTR_API_KEY=BG..<SNIP>..SHA
   LOGURU_LEVEL=INFO
   VULTR_FWGROUP_NAME=some-group-name
   TCP_PORTS=22,80,443
   UDP_PORTS=53
   ```
6. To install the script dependencies run `pipenv install`.

# Usage

To run the script simply execute: `pipenv run ./vultr.py`