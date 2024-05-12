package com.rettermobile.rio.util

import android.text.TextUtils
import com.auth0.android.jwt.JWT
import com.google.gson.Gson
import com.rettermobile.rio.Preferences
import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.service.model.RioTokenModel

object TokenData {

    var token: RioTokenModel? = null

    var tokenUpdateListener: (() -> Unit)? = null

    private val gson = Gson()

    fun isTokenNull(): Boolean = token == null

    fun initialize() {
        val infoJson = Preferences.getString(Preferences.Keys.TOKEN_INFO)

        if (!TextUtils.isEmpty(infoJson)) {
            try {
                token = gson.fromJson(infoJson, RioTokenModel::class.java)

                if (TextUtils.equals(token?.accessToken?.projectId(), RioConfig.projectId)) {
                    if (isRefreshTokenExpired(token)) {
                        // signOut
                        setTokenData(null)
                        RioLogger.log("TokenData.init tokenInfo=null")
                    } else {
                        RioLogger.log("TokenData.init tokenInfo OK")
                    }
                } else {
                    setTokenData(null)
                    RioLogger.log("TokenData.init DIFFERENT PROJECT ID!! token setted null!")
                }
            } catch (e: Exception) {
                RioLogger.log("TokenData.init tokenInfo exception ${e.message}")
                setTokenData(null)
            }
        }
    }

    fun setTokenData(data: RioTokenModel?) {
        val isStatusChanged = data?.accessToken?.jwtUserId() != TokenManager.userId()

        if (data != null) {
            // Save to device
            RioLogger.log("TokenData.setValue save device")

            token = data
            Preferences.setString(Preferences.Keys.TOKEN_INFO, gson.toJson(data))
        } else {
            // Logout
            token = null
            RioLogger.log("TokenData.setValue LOGOUT")
            Preferences.deleteKey(Preferences.Keys.TOKEN_INFO)
            Preferences.deleteKey(Preferences.Keys.TOKEN_INFO_DELTA)
            Preferences.clearAllData()
        }

        if (isStatusChanged) {
            RioLogger.log("TokenData.setValue isStatusChanged: true user:${Gson().toJson(TokenManager.user())}")
            tokenUpdateListener?.invoke()
        } else {
            RioLogger.log("TokenData.setValue isStatusChanged: false")
        }
    }

    fun isAccessTokenExpired(): Boolean {
        return token?.let {
            if (isRefreshTokenExpired(it)) {
                return true
            }

            val jwtAccess = JWT(it.accessToken)
            val accessTokenExpiresAt = jwtAccess.getClaim("exp").asLong()!!

            val now = (System.currentTimeMillis() / 1000) - TokenManager.deltaTime() + 60

            val isExpired = now >= accessTokenExpiresAt

            RioLogger.log("TokenData.isAccessTokenExpired accessToken: ${it.accessToken}")
            RioLogger.log("TokenData.isAccessTokenExpired isExpired: $isExpired")

            isExpired
        } ?: run {
            RioLogger.log("TokenData.isAccessTokenExpired tokenInfo is null!!!")
            true
        }
    }

    private fun isRefreshTokenExpired(token: RioTokenModel?): Boolean {
        if (token == null) return true

        val jwtAccess = JWT(token.refreshToken)
        val refreshTokenExpiresAt = jwtAccess.getClaim("exp").asLong()!!

        val now = (System.currentTimeMillis() / 1000) - TokenManager.deltaTime() + 24 * 60 * 60

        val isExpired = now >= refreshTokenExpiresAt

        RioLogger.log("TokenData.isRefreshTokenExpired refreshToken: ${token.refreshToken}")
        RioLogger.log("TokenData.isRefreshTokenExpired isExpired: $isExpired")

        return isExpired
    }
}