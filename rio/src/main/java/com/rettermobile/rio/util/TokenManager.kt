package com.rettermobile.rio.util

import android.text.TextUtils
import com.auth0.android.jwt.JWT
import com.google.gson.Gson
import com.rettermobile.rio.Preferences
import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioFirebaseManager
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.model.RioUser
import com.rettermobile.rio.service.auth.RioAuthServiceImp
import com.rettermobile.rio.service.model.RioTokenModel
import com.rettermobile.rio.service.model.exception.TokenFailException
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * Created by semihozkoroglu on 10.12.2021.
 */
object TokenManager {
    private val mutex = Mutex()

    var tokenUpdateListener: (() -> Unit)? = null
    var clearListener: (() -> Unit)? = null

    private val gson = Gson()

    private var tokenInfo: RioTokenModel? = null
        get() {
            val infoJson = Preferences.getString(Preferences.Keys.TOKEN_INFO)

            return gson.fromJson(infoJson, RioTokenModel::class.java)
        }
        set(value) {
            val isStatusChanged = value?.accessToken?.jwtUserId() != userId()

            field = value

            if (value != null) {
                // Save to device
                RioLogger.log("TokenManager.setValue save device")

                value.accessToken.jwtIat()?.let { iat ->
                    val diff = (System.currentTimeMillis() / 1000) - iat
                    RioLogger.log("TokenManager.setValue set time difference $diff")
                    Preferences.setLong(Preferences.Keys.TOKEN_INFO_DELTA, diff)
                }

                Preferences.setString(Preferences.Keys.TOKEN_INFO, gson.toJson(value))
            } else {
                // Logout
                RioLogger.log("TokenManager.setValue LOGOUT")
                Preferences.deleteKey(Preferences.Keys.TOKEN_INFO)
                Preferences.deleteKey(Preferences.Keys.TOKEN_INFO_DELTA)
            }

            if (isStatusChanged) {
                RioLogger.log("TokenManager.setValue isStatusChanged: true user:${Gson().toJson(user())}")
                tokenUpdateListener?.invoke()
            } else {
                RioLogger.log("TokenManager.setValue isStatusChanged: false")
            }
        }

    init {
        val infoJson = Preferences.getString(Preferences.Keys.TOKEN_INFO)

        if (!TextUtils.isEmpty(infoJson)) {
            try {
                val token = gson.fromJson(infoJson, RioTokenModel::class.java)

                tokenInfo =
                    if (TextUtils.equals(token.accessToken.projectId(), RioConfig.projectId)) {
                        if (isRefreshTokenExpired(token)) {
                            // signOut
                            RioLogger.log("TokenManager.init tokenInfo=null")
                            null
                        } else {
                            RioLogger.log("TokenManager.init tokenInfo OK")
                            token
                        }
                    } else {
                        RioLogger.log("TokenManager.init tokenInfo project id changed set as null")
                        null
                    }
            } catch (e: Exception) {
                RioLogger.log("TokenManager.init tokenInfo exception ${e.message}")
            }
        }
    }

    private fun isAccessTokenExpired(): Boolean {
        if (isRefreshTokenExpired(tokenInfo!!)) {
            return true
        }

        val jwtAccess = JWT(tokenInfo!!.accessToken)
        val accessTokenExpiresAt = jwtAccess.getClaim("exp").asLong()!!

        val now = (System.currentTimeMillis() / 1000) - deltaTime() + 30

        val isExpired =
            now >= accessTokenExpiresAt  // now + 280 -> only wait 20 seconds for debugging

        RioLogger.log("TokenManager.isAccessTokenExpired accessToken: ${tokenInfo!!.accessToken}")
        RioLogger.log("TokenManager.isAccessTokenExpired isExpired: $isExpired")

        return isExpired
    }

    private fun isRefreshTokenExpired(token: RioTokenModel): Boolean {
        val jwtAccess = JWT(token.refreshToken)
        val refreshTokenExpiresAt = jwtAccess.getClaim("exp").asLong()!!

        val now = (System.currentTimeMillis() / 1000) - deltaTime() + 24 * 60 * 60

        val isExpired =
            now >= refreshTokenExpiresAt  // now + 280 -> only wait 20 seconds for debugging

        RioLogger.log("TokenManager.isRefreshTokenExpired refreshToken: ${token.refreshToken}")
        RioLogger.log("TokenManager.isRefreshTokenExpired isExpired: $isExpired")

        return isExpired
    }

    suspend fun authenticate(customToken: String) {
        val res = runCatching { RioAuthServiceImp.authWithCustomToken(customToken) }

        return if (res.isSuccess) {
            RioLogger.log("authWithCustomToken success")

            val token = res.getOrNull()

            RioFirebaseManager.authenticate(token?.firebase)

            tokenInfo = token

            RioLogger.log("authWithCustomToken token setted")
        } else {
            RioLogger.log("authWithCustomToken fail ${res.exceptionOrNull()?.stackTraceToString()}")

            clearListener?.invoke()

            throw res.exceptionOrNull() ?: TokenFailException("AuthWithCustomToken fail")
        }
    }

    suspend fun checkToken() {
        // Token info control
        RioLogger.log("TokenManager.checkToken locked")
        mutex.withLock {
            RioLogger.log("TokenManager.checkToken started")

            if (!TextUtils.isEmpty(accessToken())) {
                if (isAccessTokenExpired()) {
                    val refreshToken = tokenInfo?.refreshToken!!

                    // Delete from device
                    RioLogger.log("TokenManager.checkToken delete token info from device")
                    Preferences.deleteKey(Preferences.Keys.TOKEN_INFO)
                    Preferences.deleteKey(Preferences.Keys.TOKEN_INFO_DELTA)

                    val res = runCatching { RioAuthServiceImp.refreshToken(refreshToken) }

                    if (res.isSuccess) {
                        RioLogger.log("TokenManager.checkToken refreshToken success")

                        tokenInfo = res.getOrNull()
                    } else {
                        RioLogger.log("TokenManager.checkToken refreshToken fail signOut called")

                        RioLogger.log("TokenManager.checkToken refreshToken fail")

                        clearListener?.invoke()

                        throw res.exceptionOrNull()
                            ?: TokenFailException("AuthWithCustomToken fail")
                    }
                }
            }

            if (RioFirebaseManager.isNotAuthenticated()) {
                RioFirebaseManager.authenticate(tokenInfo?.firebase)
            }

            RioLogger.log("TokenManager.checkToken ended")
            RioLogger.log("TokenManager.checkToken released")
        }
    }

    fun clear() {
        RioLogger.log("token cleared")
        tokenInfo = null
    }

    fun accessToken() = tokenInfo?.accessToken

    private fun deltaTime() = Preferences.getLong(Preferences.Keys.TOKEN_INFO_DELTA, 0)

    fun userId() = tokenInfo?.accessToken?.jwtUserId()

    fun userIdentity() = tokenInfo?.accessToken?.jwtIdentity()

    fun user(): RioUser? {
        return tokenInfo?.let {
            val userId = it.accessToken.jwtUserId()

            RioUser(userId, userId.isNullOrEmpty())
        } ?: kotlin.run { null }
    }
}