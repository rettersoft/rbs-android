package com.rettermobile.rio.service

import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.rettermobile.rio.util.RioRegion
import okhttp3.Interceptor
import okhttp3.logging.HttpLoggingInterceptor

/**
 * Created by semihozkoroglu on 20.01.2022.
 */
class RioNetworkConfig(
    var region: RioRegion? = null,
    var customDomain: String? = null,
    var sslPinningEnabled: Boolean = true,
    var interceptor: Interceptor? = null,
    var networkInterceptor: Interceptor? = null,
    var gson: Gson = GsonBuilder().create(),
    var headerInterceptor: HeaderInterceptor? = null,
    var firebaseEnable: Boolean = true,
    var logLevel: HttpLoggingInterceptor.Level = HttpLoggingInterceptor.Level.BODY
) {
    private fun init(builder: Builder): RioNetworkConfig {
        if (builder.region == null && builder.customDomain == null) {
            throw Exception("Region or customDomain cannot be empty!")
        } else if (builder.customDomain != null && builder.customDomain!!.startsWith("http")) {
            throw Exception("Please enter the custom domain without http or https!")
        }

        return RioNetworkConfig(
            builder.region,
            builder.customDomain,
            builder.sslPinningEnabled,
            builder.interceptor,
            builder.networkInterceptor,
            builder.gson,
            builder.headerInterceptor,
            builder.firebaseEnable,
            builder.logLevel,
        )
    }

    companion object {
        inline fun build(block: Builder.() -> Unit): RioNetworkConfig {
            return Builder().apply(block).build()
        }
    }

    class Builder {
        var region: RioRegion? = null
        var customDomain: String? = null
        var sslPinningEnabled: Boolean = true
        var interceptor: Interceptor? = null
        var networkInterceptor: Interceptor? = null
        var gson: Gson = GsonBuilder().create()
        var headerInterceptor: HeaderInterceptor? = null
        var firebaseEnable: Boolean = true
        var logLevel: HttpLoggingInterceptor.Level = HttpLoggingInterceptor.Level.BODY

        fun build() = RioNetworkConfig().init(this)
    }

    interface HeaderInterceptor {
        fun headers(): List<Pair<String, String>>
    }
}