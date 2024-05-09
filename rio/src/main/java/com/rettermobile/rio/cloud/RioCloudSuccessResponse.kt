package com.rettermobile.rio.cloud

import okhttp3.Headers

/**
 * Created by semihozkoroglu on 19.12.2021.
 */
class RioCloudSuccessResponse<T>(val headers: Headers, val code: Int, val body: T?, val rawBody: String?)