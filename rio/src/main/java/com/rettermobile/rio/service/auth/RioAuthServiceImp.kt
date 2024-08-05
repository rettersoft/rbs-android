package com.rettermobile.rio.service.auth

import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.service.RioNetwork
import com.rettermobile.rio.service.model.AuthRequest
import com.rettermobile.rio.service.model.RefreshTokenRequest
import com.rettermobile.rio.service.model.RioTokenModel
import okhttp3.ResponseBody

/**
 * Created by semihozkoroglu on 22.11.2020.
 */
object RioAuthServiceImp {

    private var api: RioAuthService = RioNetwork().getAuthConnection()

    suspend fun refreshToken(accessToken: String, refreshToken: String): RioTokenModel {
        RioLogger.log("refreshToken started")

        return api.refresh("${RioConfig.projectId}/TOKEN/refresh", RefreshTokenRequest(accessToken, refreshToken), RioConfig.culture)
    }

    suspend fun authWithCustomToken(customToken: String): RioTokenModel {
        RioLogger.log("authWithCustomToken started")

        return api.auth("${RioConfig.projectId}/TOKEN/auth", AuthRequest(customToken), RioConfig.culture)
    }

    suspend fun signOut(type: String): ResponseBody {
        RioLogger.log("signOut started")

        return api.signOut("${RioConfig.projectId}/TOKEN/signOut?type=$type", RioConfig.culture)
    }
}