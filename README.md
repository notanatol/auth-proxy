# auth-proxy

This application will run between the bee instance and the outer world providing authentication and authorization capabilities.

To start:

> go run . --internal-port 1643 --external-port 1645 --ingress-url 'http://localhost:1633'

To access an internal endpoint (whitelisted):

```sh
curl -vv localhost:1643/pins
```

you should get a similar response:

```json
{
   "references" : []
}
```

To access an external endpoint (blacklisted):

```sh
curl -vv localhost:1645/node
```

The response code should be `404` since `node` endpoint is blocklisted on the external route.
