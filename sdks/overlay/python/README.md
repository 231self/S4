# Maskura Python SDK (`maskura-client`)

Generated Python client for the Maskura Gateway API. The canonical import is
`maskura_client`; the permanent <code>s4&#95;client</code> compatibility namespace is included
in the same distribution.

## Requirements

Python 3.9+

## Installation

Install directly from the current S4 repository:

```sh
pip install "git+https://github.com/231self/S4.git#subdirectory=sdks/python"
```

Release downloads can be installed directly as well:

```sh
pip install https://github.com/231self/S4/releases/latest/download/maskura-python-sdk.tar.gz
```

## Usage

```python
from maskura_client import Configuration, MaskuraClient

configuration = Configuration(host="https://api.s4.231self.com")
client = MaskuraClient(
    endpoint=configuration.host,
    access_key="s4_example",
    secret_key="s4s_example",
)
```

## Tests

```sh
pytest
```
