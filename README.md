OpenID Connect for Jitsi in GO

tested:
- [x] keycloak
- [x] goauthentik

this code based on https://github.com/MarcelCoding/jitsi-openid


dockerhub: https://hub.docker.com/r/bluffy2006/jitsi-oidc   
github: https://github.com/bluffy/jitsi-oidc.git

# docker-compose.yaml
```yml
version: '3.8'
services:
    jitsi-openid:
        image: bluffy2006/jitsi-oidc:latest
        restart: always
        environment:     
            JITSI_SECRET: ${JWT_APP_SECRET}                         # jitsi-token-secret
            JITSI_URL: https://meet.jitsi-url.com                   # jitsi-url
            JITSI_SUB: meet.jitsi-url.com                           # jitsi-domaine without https
            ISSUER_BASE_URL: https://open-id-server/realms/master   # open-id issuer
            BASE_URL: https://auth-meet.jitsi-url.com               # this app url
            CLIENT_ID: ${OPEN_ID_CLIENT_ID}                         # open-id client-id
            SECRET: ${OPEN_ID_SECRET}                               # open-id client-secert
        networks:
           - proxy
        ports:
           - '3000:3001'    
        labels:
           - "traefik.enable=true"      
           - "traefik.http.routers.jitsi-auth.rule=Host(`auth-meet.jitsi-url.com`)"
           - "traefik.http.routers.jitsi-auth.entrypoints=websecure"
           - "traefik.http.routers.jitsi-auth.tls.certresolver=le"   
           - "treafik.http.services.jitsi-auth.loadbalancer.server.port=3001"
```


