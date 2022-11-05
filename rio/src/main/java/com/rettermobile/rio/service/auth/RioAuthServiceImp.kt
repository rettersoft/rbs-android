package com.rettermobile.rio.service.auth

import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.service.RioNetwork
import com.rettermobile.rio.service.model.RioTokenModel
import com.rettermobile.rio.util.TokenManager
import okhttp3.ResponseBody

/**
 * Created by semihozkoroglu on 22.11.2020.
 */
object RioAuthServiceImp {

    private var api: RioAuthService = RioNetwork().getAuthConnection()

    suspend fun refreshToken(refreshToken: String): RioTokenModel {
        RioLogger.log("refreshToken started")

        return api.refresh("${RioConfig.projectId}/AUTH/refreshToken", refreshToken, RioConfig.culture)
    }

    suspend fun authWithCustomToken(customToken: String): RioTokenModel {
        RioLogger.log("authWithCustomToken started")

        return api.auth("${RioConfig.projectId}/AUTH/authWithCustomToken", customToken, RioConfig.culture)
    }

    suspend fun signOut(): ResponseBody {
        RioLogger.log("authWithCustomToken started")

        return api.signOut("${RioConfig.projectId}/AUTH/signOut", TokenManager.accessToken(), RioConfig.culture)
    }
}