#!/bin/zsh

curl --request POST \
  --url 'https://lumeer.eu.auth0.com/oauth/token' \
  --header 'content-type: application/json' \
  --data '{"grant_type":"password", "username":"aturing@lumeer.io", "password":"$password", "audience":"http://localhost:8080/", "scope":"openid profile", "client_id": "Hjee0La2DjlYjIH5ClCx3Xnfaj02n2On", "client_secret": "ZcyJKbH5994vtemZYSo_ZrwRYrwleCsns2vOvM5IOsSyzrJqo9k-SCeBSs5asyzS" }'

#https://lumeer.eu.auth0.com/userinfo
