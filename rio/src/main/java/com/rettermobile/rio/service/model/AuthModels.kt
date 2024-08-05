package com.rettermobile.rio.service.model

data class RefreshTokenRequest(val accessToken: String, val refreshToken: String)
data class AuthRequest(val customToken: String)