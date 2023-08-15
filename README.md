# Go auth jwt microservice



## Run

Clone repository
```shell
git clone github.com/SvytDola/go-auth-jwt
```
Then run up
```shell
docker-compose up
```

Server is running on http://localhost:8080


## Paths

```
GET /auth/token?user_id=GUID
```

```
GET /auth/refresh-token?refresh_token=refreshToken&access_token=accessToken
```
