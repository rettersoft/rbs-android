package com.rettermobile.rbs

import android.content.Context
import android.util.Log
import com.rettermobile.rbs.util.Logger
import com.rettermobile.rbs.util.RBSRegion

/**
 * Created by semihozkoroglu on 10.12.2021.
 */
object RBSLogger {

    var logListener: Logger? = null

    private val logger = object : Logger {
        override fun log(message: String) {
            Log.e("RBSService", message)
            logListener?.log(message)
        }
    }

    fun log(message: String) {
        logger.log(message = message)
    }
}