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
import java.util.*

/**
 * Created by semihozkoroglu on 10.12.2021.
 */
object TokenManager {
    private val mutex = Mutex()

    var clearListener: (() -> Unit)? = null
    var tokenRefreshListener: (() -> Unit)? = null

    suspend fun authenticate(customToken: String) {
        val res = runCatching { RioAuthServiceImp.authWithCustomToken(customToken) }

        return if (res.isSuccess) {
            RioLogger.log("authWithCustomToken success")

            val token = res.getOrNull()

            RioFirebaseManager.authenticate(token?.firebase, signIn = true)

            TokenData.setTokenData(token)
            calculateDelta()

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
                if (TokenData.isAccessTokenExpired()) {
                    val refreshToken = TokenData.token?.refreshToken!!

                    refreshWithRetry(refreshToken)
                }
            }

            if (RioFirebaseManager.isNotAuthenticated()) {
                RioFirebaseManager.authenticate(TokenData.token?.firebase, signIn = false)
            }

            RioLogger.log("TokenManager.checkToken ended")
            RioLogger.log("TokenManager.checkToken released")
        }
    }

    private suspend fun refreshWithRetry(refreshToken: String, retryCount: Int = 1) {
        RioLogger.log("TokenManager.retryWithSub retryCount: $retryCount")

        val res = runCatching {
            RioAuthServiceImp.refreshToken(accessToken() ?: "", refreshToken)
        }

        if (res.isSuccess) {
            RioLogger.log("TokenManager.refreshWithRetry refreshToken success")

            TokenData.setTokenData(res.getOrNull())
            calculateDelta()

            tokenRefreshListener?.invoke()
        } else {
            if (retryCount > 3) {
                RioLogger.log("TokenManager.refreshWithRetry refreshToken fail signOut called")

                RioLogger.log("TokenManager.refreshWithRetry refreshToken fail")

                /**
                 * don't logout user if token didn't refreshed
                 * clearListener?.invoke()
                 */
                throw res.exceptionOrNull() ?: TokenFailException("AuthWithCustomToken fail")
            } else {
                Thread.sleep((100 * retryCount).toLong())

                refreshWithRetry(refreshToken, retryCount = retryCount + 1)
            }
        }
    }

    private fun calculateDelta() {
        RioLogger.log("TokenManager.calculateDelta called")

        accessToken()?.jwtIat()?.let { iat ->
            val now = (System.currentTimeMillis() / 1000)

            RioLogger.log("TokenManager.calculateDelta now: $now iat: $iat")

            val diff = now - iat
            RioLogger.log("TokenManager.calculateDelta set time difference $diff")
            Preferences.setLong(Preferences.Keys.TOKEN_INFO_DELTA, diff)
        }
    }

    fun clear() {
        RioLogger.log("token cleared")
        TokenData.setTokenData(null)
    }

    fun accessToken() = TokenData.token?.accessToken

    fun deltaTime() = Preferences.getLong(Preferences.Keys.TOKEN_INFO_DELTA, 0)

    fun userId() = TokenData.token?.accessToken?.jwtUserId()

    fun userIdentity() = TokenData.token?.accessToken?.jwtIdentity()

    fun user(): RioUser? {
        return TokenData.token?.let {
            val userId = it.accessToken.jwtUserId()
            val isEndUser = it.accessToken.jwtIdentity() == "enduser"

            RioUser(userId, !isEndUser)
        } ?: kotlin.run { null }
    }

    fun getDeviceId(): String {
        val deviceId = Preferences.getString(Preferences.Keys.DEVICE_ID)

        if (!TextUtils.isEmpty(deviceId)) {
            return deviceId!!
        }

        val uid: String = try {
            UUID.randomUUID().toString()
        } catch (e: Exception) {
            System.currentTimeMillis().toString() + "-" + System.currentTimeMillis().toString()
        }

        Preferences.setString(Preferences.Keys.DEVICE_ID, uid)

        return uid
    }
}