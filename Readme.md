# JWT Token Generator

![GitHub release (latest by date)](https://img.shields.io/github/v/release/alexanderwolz/token-generator)
![GitHub](https://img.shields.io/github/license/alexanderwolz/keycloak-docker-group-role-mapper)
![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/alexanderwolz/token-generator)
![GitHub all releases](https://img.shields.io/github/downloads/alexanderwolz/token-generator/total?color=informational)

## 🧑‍💻 About

This repository provides a toolkit to create JWT tokens

## 🛠️ Build
1. Create jar resource using ```./gradlew clean build```
2. Execute jar using ```java -jar build/libs/token-generator-1.1.jar```

## ⚙️ Example
1. Create RS256 tokens: ```java -jar build/libs/token-generator-1.1.jar -c privateKey issuer subject audience expirationInSeconds```
2. Validate tokens: ```java -jar build/libs/token-generator-1.1.jar publicKey token```
- - -

Made with ❤️ in Bavaria
<br>
© 2023, <a href="https://www.alexanderwolz.de"> Alexander Wolz