```yaml
extensions:
  bearertokenauth:
    scheme: "APIKey"
    token: "<ENCODED_ELASTICSEARCH_APIKEY>"

  apmconfig:
    opamp:
      protocols:
        http:
          # Default is localhost:4320
          # endpoint: "<CUSTOM_OPAMP_ENDPOINT>"
    source:
      elasticsearch:
        endpoint: "<ELASTICSEARCH_ENDPOINT>"
        auth:
          authenticator: bearertokenauth
```

:::{note}
For comprehensive authentication configuration options, see [Authentication methods](/reference/edot-collector/config/authentication-methods.md).
:::