# AuthMicroservice - A FastAPI Application with 2FA JWT Authentication

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtoken&logoColor=white)

This is a demo application built with FastAPI that demonstrates JWT (JSON Web Token) authentication. The application includes endpoints for user signup, token issuance, 2fa token issuance, token refreshing and getting public keys.


## API Endpoints:

- **`/signup`**:  
  Creates a new user account in the database.  
  **Method**: ``POST``
  
- **`/token`**:  
  Returns a pair of access and refresh JWT tokens.  
  **Method**: `POST`
  
- **`/token/2fa`**:  
  Verifies 2FA (TOTP) and returns a pair of access and refresh JWT tokens.  
  **Method**: `POST`

- **`/refresh`**:  
  Returns a new pair of access and refresh tokens. You need to provide a valid refresh token.  
  **Method**: `POST`

- **`/public-keys`**:  
  Returns public key ids
  **Method**: `POST`

## API Documentation:
You can test and explore the API using the interactive documentation available at:  
[Swagger Docs](https://127.0.0.1:8000/docs)
