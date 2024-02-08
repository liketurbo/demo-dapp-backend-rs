# demo-dapp-backend-rs

Here is the [frontend example](https://github.com/ton-connect/demo-dapp-with-backend) that goes with this backend.

The authorization process is as follows:

1. The client fetches the payload to be signed by the wallet:

    ```json
    // <host>/ton-proof/generatePayload

    // response
    {
      "payload": "E5B4ARS6CdOI2b5e1jz0jnS-x-a3DgfNXprrg_3pec0="
    }
    ```

2. The client connects to the wallet via TonConnect 2.0 and passes the `ton_proof` request with the specified payload. Refer to the [frontend SDK](https://github.com/ton-connect/sdk/tree/main/packages/sdk) for more details.

3. The user approves the connection, and the client receives the signed payload with additional prefixes.

4. The client sends the signed result to the backend. The backend checks the correctness of all prefixes and the signature and returns the auth token:

    ```json

    // <host>/ton-proof/checkProof

    // request
    {
      "address": "0:f63660ff947e5fe6ed4a8f729f1b24ef859497d0483aaa9d9ae48414297c4e1b", // user's address
      "network": "-239", // "-239" for mainnet and "-1" for testnet
      "proof": {
        "timestamp": 1668094767, // unix epoch seconds
        "domain": {
          "lengthBytes": 21,
          "value": "ton-connect.github.io"
        },
        "signature": "28tWSg8RDB3P/iIYupySINq1o3F5xLodndzNFHOtdi16Z+MuII8LAPnHLT3E6WTB27//qY4psU5Rf5/aJaIIAA==",
        "payload": "E5B4ARS6CdOI2b5e1jz0jnS-x-a3DgfNXprrg_3pec0=", // payload from step 1
        "state_init": "..."
      }
    }

    // response
    {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhZGRyZXNzIjoiMDpmNjM2NjBmZjk0N2U1ZmU2ZWQ0YThmNzI5ZjFiMjRlZjg1OTQ5N2QwNDgzYWFhOWQ5YWU0ODQxNDI5N2M0ZTFiIiwiZXhwIjoxNjY4MDk4NDkwfQ.13sg3Mgt2hT9_vChan3bmQkp_Wsigj9YjSoKABTsVGA"
    }
    ```

5. The client can access auth-required endpoints:

    ```json
    // <host>/dapp/getAccountInfo?network=-239
    // Bearer <token>

    // response
    {
      "address": "0:f63660ff947e5fe6ed4a8f729f1b24ef859497d0483aaa9d9ae48414297c4e1b"
    }
    ```

See more details in the [Signing and Verification](https://docs.ton.org/develop/dapps/ton-connect/sign).
