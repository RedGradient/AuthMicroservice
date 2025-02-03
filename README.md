# JWTAuthDemo - A FastAPI Demo Application with JWT Authentication

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtoken&logoColor=white)

This is a demo application built with FastAPI that demonstrates how to implement JWT (JSON Web Token) authentication. The application includes endpoints for user signup, token issuance, token refreshing, and accessing protected resources.


## API Endpoints:

- **`/signup`**:  
  Creates a new user account in the database.  
  **Method**: ``POST``
  
- **`/token`**:  
  Returns a pair of access and refresh JWT tokens.  
  **Method**: `POST`
  
- **`/refresh`**:  
  Returns a new pair of access and refresh tokens. You need to provide a valid refresh token.  
  **Method**: `POST`
  
- **`/users`**:  
  A protected endpoint. Requires authentication. Returns a list of all users in the system.  
  **Method**: `GET`

## API Documentation:
You can test and explore the API using the interactive documentation available at:  
[Swagger Docs](https://127.0.0.1:8000/docs)