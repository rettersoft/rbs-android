package com.rettermobile.rio.cloud

import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.service.cloud.RioCloudServiceImp
import com.rettermobile.rio.service.model.RioInstanceResponse
import com.rettermobile.rio.service.model.exception.NullBodyException
import com.rettermobile.rio.util.RioActions
import com.rettermobile.rio.util.RioHttpMethod
import com.rettermobile.rio.util.TokenManager
import com.rettermobile.rio.util.parseResponse
import kotlinx.coroutines.*

/**
 * Created by semihozkoroglu on 13.12.2021.
 */
class RioCloudObject(val options: RioCloudObjectOptions, var instance: RioInstanceResponse? = null) {

    var user = RioCloudUserObjectState(options)
    var role = RioCloudRoleObjectState(options)
    var public = RioCloudPublicObjectState(options)

    inline fun <reified T> call(
        callOptions: RioCallMethodOptions,
        noinline onSuccess: ((RioCloudSuccessResponse<T>) -> Unit)? = null,
        noinline onError: ((Throwable?) -> Unit)? = null
    ) {
        if (callOptions.retry == null) callOptions.retry = RioConfig.retryConfig

        GlobalScope.launch {
            async(Dispatchers.IO) {
                var delayMillis = (callOptions.retry!!.delay * callOptions.retry!!.rate).toLong()

                for (i in 0..callOptions.retry!!.count) {
                    RioLogger.log("RioCloudObject.call current try count: $i")
                    val res = runCatching {
                        TokenManager.checkToken()

                        RioCloudServiceImp.exec(
                            RioActions.CALL,
                            RioServiceParam(options, callOptions)
                        )
                    }

                    if (res.isSuccess) {
                        try {
                            val response = res.getOrNull()

                            if (response == null) {
                                withContext(Dispatchers.Main) { onError?.invoke(NullBodyException("null body returned")) }
                                break
                            } else {
                                if (response.isSuccessful) {
                                    val clazz = if (callOptions.type != null) {
                                        callOptions.type
                                    } else {
                                        T::class.java
                                    }

                                    val body = response.body()?.string()

                                    withContext(Dispatchers.Main) { onSuccess?.invoke(RioCloudSuccessResponse(response.headers(), response.code(), parseResponse(clazz!!, body), body)) }
                                    break
                                } else {
                                    if (response.code() == 570) {
                                        if (i == callOptions.retry!!.count) {
                                            RioLogger.log("RioCloudObject.call reached max retry count = $i and return exception")
                                            withContext(Dispatchers.Main) { onError?.invoke(RioErrorResponse(response.headers(), response.code(), response.errorBody()?.string())) }
                                            break
                                        } else {
                                            RioLogger.log("RioCloudObject.call delay($delayMillis millisecond) for attempt new request")
                                            delay(delayMillis)
                                            delayMillis = (delayMillis * callOptions.retry!!.rate).toLong()
                                        }
                                    } else {
                                        withContext(Dispatchers.Main) { onError?.invoke(RioErrorResponse(response.headers(), response.code(), response.errorBody()?.string())) }
                                        break
                                    }
                                }
                            }
                        } catch (e: Exception) {
                            RioLogger.log("RioCloudObject.call exception: ${e.message}")
                            withContext(Dispatchers.Main) { onError?.invoke(e) }
                            break
                        }
                    } else {
                        val exception = res.exceptionOrNull()
                        RioLogger.log("RioCloudObject.call exception: ${exception?.message}")
                        withContext(Dispatchers.Main) { onError?.invoke(exception) }
                        break
                    }
                }
            }
        }
    }

    fun listInstances(
        onSuccess: ((RioCloudListResponse?) -> Unit)? = null,
        onError: ((Throwable?) -> Unit)? = null
    ) {
        GlobalScope.launch {
            async(Dispatchers.IO) {
                val res = runCatching {
                    TokenManager.checkToken()

                    RioCloudServiceImp.exec(
                        RioActions.LIST,
                        RioServiceParam(RioCloudObjectOptions().apply {
                            classId = options.classId
                        }, RioCallMethodOptions().apply {
                            httpMethod = RioHttpMethod.GET
                        })
                    )
                }

                if (res.isSuccess) {
                    try {
                        val response = res.getOrNull()

                        if (response == null) {
                            withContext(Dispatchers.Main) { onError?.invoke(NullBodyException("null body returned")) }
                        } else {
                            if (response.isSuccessful) {
                                withContext(Dispatchers.Main) { onSuccess?.invoke(parseResponse(RioCloudListResponse::class.java, response.body()?.string())) }
                            } else {
                                withContext(Dispatchers.Main) { onError?.invoke(RioErrorResponse(response.headers(), response.code(), response.errorBody()?.string())) }
                            }
                        }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) { onError?.invoke(e) }
                    }
                } else {
                    withContext(Dispatchers.Main) { onError?.invoke(res.exceptionOrNull()) }
                }
            }
        }
    }

    fun unsubscribeStates() {
        user.removeListener()
        role.removeListener()
        public.removeListener()
    }
}