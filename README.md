## Generate certificate and key

### Service Provider

```sh
openssl req -x509 -new -newkey rsa:2048 -nodes -subj '/C=US/ST=California/L=San Francisco/O=JankyCo/CN=Test Service Provider' -keyout sp-private-key.pem -out sp-public-cert.pem -days 7300
```

```sh
openssl x509 -pubkey -noout -in sp-public-cert.pem -out sp-public-key.pem
```
