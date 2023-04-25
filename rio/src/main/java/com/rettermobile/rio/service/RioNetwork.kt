package com.rettermobile.rio.service

import com.google.gson.GsonBuilder
import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.service.auth.RioAuthService
import com.rettermobile.rio.service.cloud.RioCloudService
import com.rettermobile.rio.util.TokenManager
import okhttp3.CacheControl
import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.util.concurrent.TimeUnit

/**
 * Created by semihozkoroglu on 22.11.2020.
 */
class RioNetwork {

    private var authService: RioAuthService? = null
    private var cloudService: RioCloudService? = null

    private fun provideCertificate(): CertificatePinner {
        val certificate = CertificatePinner.Builder()
            .add("*.rtbs.io", "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=")
            .add("*.rtbs.io", "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=")
            .add("*.rtbs.io", "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=")
            .add("*.rtbs.io", "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=")
            .add("*.rtbs.io", "sha256/KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=")
            .add("*.rtbs.io", "sha256/FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ=")
            .add("*.rettermobile.com", "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=")
            .add("*.rettermobile.com", "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=")
            .add("*.rettermobile.com", "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=")
            .add("*.rettermobile.com", "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=")
            .add("*.rettermobile.com", "sha256/KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=")
            .add("*.rettermobile.com", "sha256/FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ=")
            .add("*.retter.io", "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=")
            .add("*.retter.io", "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=")
            .add("*.retter.io", "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=")
            .add("*.retter.io", "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=")
            .add("*.retter.io", "sha256/KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=")
            .add("*.retter.io", "sha256/FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ=")

        if (!RioConfig.config.customDomain.isNullOrEmpty()) {
            val customDomain =
                RioConfig.config.customDomain!!.replace("https://", "").replace("http://", "")

            certificate.add(customDomain, "sha256/++MBgDH5WGvL9Bcn5Be30cRcL0f5O+NyoXuWtQdX1aI=")
            certificate.add(customDomain, "sha256/f0KW/FtqTjs108NpYj42SrGvOB2PpxIVM8nWxjPqJGE=")
            certificate.add(customDomain, "sha256/NqvDJlas/GRcYbcWE8S/IceH9cq77kg0jVhZeAPXq8k=")
            certificate.add(customDomain, "sha256/9+ze1cZgR9KO1kZrVDxA4HQ6voHRCSVNz4RdTCx4U8U=")
            certificate.add(customDomain, "sha256/KwccWaCgrnaw6tsrrSO61FgLacNgG2MMLq8GE6+oP5I=")
            certificate.add(customDomain, "sha256/FfFKxFycfaIz00eRZOgTf+Ne4POK6FgYPwhBDqgqxLQ=")
        }

        return certificate.build()
    }

    private fun provideOkHttp(): OkHttpClient {
        val builder = OkHttpClient.Builder()
        val interceptor = HttpLoggingInterceptor() {
            RioLogger.log("Okhttp: $it")
        }.apply {
            level = HttpLoggingInterceptor.Level.BODY
        }

        if (RioConfig.config.sslPinningEnabled) {
            builder.certificatePinner(provideCertificate())
        }

        builder.addInterceptor { chain ->
            val originalRequest = chain.request()

            val newRequestBuilder = originalRequest.newBuilder()

            newRequestBuilder
                .header("sdk-user-agent", "android-1.5.8")
                .header("User-Agent", httpAgent())
                .addHeader("Content-Type", "application/json;charset=UTF-8")
                .addHeader("x-rio-sdk-client", "android")
                .addHeader("installation-id", TokenManager.getDeviceId())
                .cacheControl(CacheControl.FORCE_NETWORK)

            TokenManager.accessToken()?.let {
                newRequestBuilder.addHeader("Authorization", "Bearer $it")
            }

            return@addInterceptor chain.proceed(newRequestBuilder.build())
        }

        val sessionTimeout = 120L

        builder.addInterceptor(interceptor)

        RioConfig.config.interceptor?.let { builder.addInterceptor(it) }
        RioConfig.config.networkInterceptor?.let { builder.addNetworkInterceptor(it) }

        builder.connectTimeout(sessionTimeout, TimeUnit.SECONDS)
        builder.readTimeout(sessionTimeout, TimeUnit.SECONDS)
        builder.writeTimeout(sessionTimeout, TimeUnit.SECONDS)

        builder.hostnameVerifier { hostname, session -> true }

        return builder.build()
    }

    fun getAuthConnection(): RioAuthService {
        if (authService == null) {
            val url = if (RioConfig.config.region == null) {
                "https://${RioConfig.config.customDomain}"
            } else {
                "https://api.${RioConfig.config.region!!.url}"
            }

            val retrofit = Retrofit.Builder()
                .baseUrl(url)
                .addConverterFactory(GsonConverterFactory.create(GsonBuilder().create()))
                .client(provideOkHttp())
                .build()

            authService = retrofit.create(RioAuthService::class.java)
        }

        return authService!!
    }

    fun getCloudConnection(): RioCloudService {
        if (cloudService == null) {

            val url = if (RioConfig.config.region == null) {
                "https://${RioConfig.config.customDomain}"
            } else {
                "https://api.${RioConfig.config.region!!.url}"
            }

            val retrofit = Retrofit.Builder()
                .baseUrl(url)
                .addConverterFactory(GsonConverterFactory.create(GsonBuilder().create()))
                .client(provideOkHttp())
                .build()

            cloudService = retrofit.create(RioCloudService::class.java)
        }

        return cloudService!!
    }

    private fun httpAgent() = try {
        System.getProperty("http.agent") ?: "Android"
    } catch (e: Exception) {
        "Android"
    }

}