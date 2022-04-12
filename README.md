# auth-proxy

This application will run between the bee instance and the outer world providing authentication and authorization capabilities.

To start:

> go run . --port 1633 --token-encryption-key enc-key --admin-password '$2a$12$E7ROtngtkl1ymzqXLWhgGO9Fw3Ih0heG5gDgvnewrRYeBhtoBnCrq'

To get an auth token:

```sh
curl --request POST \
  --url http://localhost:1633/auth \
  --header 'authorization: Basic OmhlbGxv' \
  --header 'content-type: application/json' \
  --data '{"role": "maintainer","expiry": 315360000}'
```

you should get a similar response:

```json
{
   "key" : "933lBcBLOM96hpPRtUL0x3G3c5ixbgkSh2mQbxyNPTY3mHAghyiui5IHgngvQsrhbLRlbS4VOrViCymKnMtX7O4/jYclDvE45D/9AJUoQvvKGhNS6upq"
}
```

To refresh it for a new one that will expire in 15 seconds:

```sh
export key=933lBcBLOM96hpPRtUL0x3G3c5ixbgkSh2mQbxyNPTY3mHAghyiui5IHgngvQsrhbLRlbS4VOrViCymKnMtX7O4/jYclDvE45D/9AJUoQvvKGhNS6upq

curl --request POST \
  --url http://localhost:1633/refresh \
  --header "authorization: Bearer $key" \
  --header 'content-type: application/json' \
  --data '{"expiry": 15}'
```
