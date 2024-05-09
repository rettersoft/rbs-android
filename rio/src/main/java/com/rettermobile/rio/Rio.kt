package com.rettermobile.rio

import android.content.Context
import android.text.TextUtils
import com.rettermobile.rio.cloud.RioCallMethodOptions
import com.rettermobile.rio.cloud.RioCloudObject
import com.rettermobile.rio.cloud.RioCloudObjectOptions
import com.rettermobile.rio.cloud.RioCloudSuccessResponse
import com.rettermobile.rio.model.RioClientAuthStatus
import com.rettermobile.rio.model.RioUser
import com.rettermobile.rio.service.RioNetworkConfig
import com.rettermobile.rio.service.RioRetryConfig
import com.rettermobile.rio.service.auth.RioAuthRequestManager
import com.rettermobile.rio.service.cloud.RioCloudRequestManager
import com.rettermobile.rio.service.model.exception.CloudNullException
import com.rettermobile.rio.util.Logger
import com.rettermobile.rio.util.RioActions
import com.rettermobile.rio.util.TokenData
import com.rettermobile.rio.util.TokenManager
import kotlinx.coroutines.*

/**
 * Created by semihozkoroglu on 22.11.2020.
 */
class Rio(
    applicationContext: Context,
    projectId: String,
    culture: String? = null,
    config: RioNetworkConfig,
    retryConfig: RioRetryConfig? = null
) {

    private val job: Job = Job()
    private val scope = CoroutineScope(Dispatchers.Default + job)

    private var authStatus: RioClientAuthStatus? = null

    init {
        RioConfig.applicationContext = applicationContext
        RioConfig.projectId = projectId
        RioConfig.culture = culture ?: "en-us"
        RioConfig.config = config
        RioConfig.retryConfig = retryConfig ?: RioRetryConfig()

        TokenData.tokenUpdateListener = { sendAuthStatus() }
        TokenManager.clearListener = { signOutMethod(type = "sdk") }

        TokenData.initialize()
    }

    private var listener: ((RioClientAuthStatus, RioUser?) -> Unit)? = null

    fun setOnClientAuthStatusChangeListener(l: (RioClientAuthStatus, RioUser?) -> Unit) {
        listener = l

        sendAuthStatus()
    }

    fun authenticateWithCustomToken(customToken: String, callback: ((Boolean, Throwable?) -> Unit)? = null) {
        scope.launch(CoroutineExceptionHandler { _, e ->
            RioLogger.log("ExceptionHandler#getCloudObject: ${e.message} \nStackTrace: ${e.stackTraceToString()}")

            callback?.invoke(false, e)
        }) {
            if (authStatus != RioClientAuthStatus.AUTHENTICATING) {
                authStatus = RioClientAuthStatus.AUTHENTICATING
                RioLogger.log("Rio.authenticateWithCustomToken authStatus setted as RioClientAuthStatus.AUTHENTICATING")

                withContext(Dispatchers.Main) {
                    listener?.invoke(RioClientAuthStatus.AUTHENTICATING, null)
                }

                if (!TextUtils.isEmpty(customToken)) {
                    val res = runCatching { RioAuthRequestManager.authenticate(customToken) }

                    if (res.isSuccess) {
                        withContext(Dispatchers.Main) { callback?.invoke(true, null) }
                    } else {
                        withContext(Dispatchers.Main) { callback?.invoke(false, res.exceptionOrNull()) }
                    }
                } else {
                    withContext(Dispatchers.Main) {
                        callback?.invoke(
                            false,
                            IllegalArgumentException("customToken must not be null or empty")
                        )
                    }
                }

                delay(3000)
                RioLogger.log("Rio.authenticateWithCustomToken authStatus setted as NULL")
                authStatus = null
            } else {
                RioLogger.log("Rio.authenticateWithCustomToken authStatus is RioClientAuthStatus.AUTHENTICATING")
                delay(3000)
                RioLogger.log("Rio.authenticateWithCustomToken authStatus setted as NULL")
                authStatus = null
            }
        }
    }

    inline fun <reified T> makeStaticCall(
        options: RioCloudObjectOptions,
        noinline onSuccess: ((RioCloudSuccessResponse<T>) -> Unit)? = null,
        noinline onError: ((Throwable?) -> Unit)? = null
    ) {
        RioCloudObject(options)
            .call(
                RioCallMethodOptions(
                    method = options.method,
                    httpMethod = options.httpMethod,
                    body = options.body,
                    headers = options.headers,
                    queries = options.queries,
                    culture = options.culture,
                    path = options.path,
                    type = options.type
                ), onSuccess, onError
            )
    }

    fun getCloudObject(
        options: RioCloudObjectOptions,
        onSuccess: ((RioCloudObject) -> Unit)? = null,
        onError: ((Throwable?) -> Unit)? = null
    ) {
        scope.launch(CoroutineExceptionHandler { _, e ->
            RioLogger.log("ExceptionHandler#getCloudObject: ${e.message} \nStackTrace: ${e.stackTraceToString()}")

            onError?.invoke(e)
        }) {
            val res = runCatching { RioCloudRequestManager.exec(action = RioActions.INSTANCE, options) }

            if (res.isSuccess) {
                if (res.getOrNull() != null) {
                    withContext(Dispatchers.Main) { onSuccess?.invoke(res.getOrNull()!!) }
                } else {
                    withContext(Dispatchers.Main) { onError?.invoke(CloudNullException("Cloud object returned null")) }
                }
            } else {
                withContext(Dispatchers.Main) { onError?.invoke(res.exceptionOrNull()) }
            }
        }
    }

    private fun sendAuthStatus() {
        scope.launch(CoroutineExceptionHandler { _, e ->
            RioLogger.log("ExceptionHandler#sendAuthStatus: ${e.message} \nStackTrace: ${e.stackTraceToString()}")
        }) {
            TokenManager.user()?.let { user ->
                withContext(Dispatchers.Main) {
                    listener?.invoke(
                        RioClientAuthStatus.SIGNED_IN,
                        user
                    )
                }
            } ?: run {
                withContext(Dispatchers.Main) {
                    listener?.invoke(
                        RioClientAuthStatus.SIGNED_OUT,
                        null
                    )
                }
            }
        }
    }

    fun getAuthStatus(): RioClientAuthStatus {
        return TokenManager.user()?.let { user ->
            RioClientAuthStatus.SIGNED_IN
        } ?: run {
            RioClientAuthStatus.SIGNED_OUT
        }
    }

    private fun signOutMethod(type: String, callback: ((Boolean, Throwable?) -> Unit)? = null) {
        RioLogger.log("signOut called")

        scope.launch(CoroutineExceptionHandler { _, e ->
            RioLogger.log("ExceptionHandler#signOut: ${e.message} \nStackTrace: ${e.stackTraceToString()}")

            clear()

            callback?.invoke(false, e)
        }) {
            val res = runCatching { RioAuthRequestManager.signOut(type) }

            clear()

            if (res.isSuccess) {
                withContext(Dispatchers.Main) { callback?.invoke(true, null) }
            } else {
                withContext(Dispatchers.Main) { callback?.invoke(false, res.exceptionOrNull()) }
            }
        }
    }

    fun signOut(callback: ((Boolean, Throwable?) -> Unit)? = null) {
        signOutMethod(type = "user", callback)
    }

    private fun clear() {
        RioLogger.log("clearSession called")

        TokenManager.clear()
        RioFirebaseManager.signOut()
    }

    fun setLoggerListener(listener: Logger) {
        RioLogger.logListener = listener
    }

    fun logEnable(enable: Boolean) {
        RioLogger.logEnable(enable)
    }
}