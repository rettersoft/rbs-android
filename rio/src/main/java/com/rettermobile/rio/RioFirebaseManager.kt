package com.rettermobile.rio

import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.DocumentReference
import com.google.firebase.firestore.FirebaseFirestore
import com.google.gson.Gson
import com.rettermobile.rio.service.model.RioFirebase
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * Created by semihozkoroglu on 10.12.2021.
 */
internal object RioFirebaseManager {

    private var app: FirebaseApp? = null
    private var auth: FirebaseAuth? = null

    suspend fun authenticate(fireInfo: RioFirebase?, signIn: Boolean) {
        if (!RioConfig.config.firebaseEnable) return

        if (fireInfo == null) return

        RioLogger.log("RIOFirebaseManager.authenticate STARTED")

//        auth?.signOut()

//        app?.let {
//            deleteApp()
//            delay(500)
//            initApp(fireInfo)
//        } ?: run { initApp(fireInfo) }

        initApp(fireInfo, signIn)
    }

//    private suspend fun deleteApp() = suspendCoroutine<Unit> { continuation ->
//        RioLogger.log("RIOFirebaseManager.deleteApp called")
//        app?.let {
//            RioLogger.log("RIOFirebaseManager.deleteApp addLifecycleEventListener added")
//            it.addLifecycleEventListener { appName, options ->
//                RioLogger.log("RIOFirebaseManager.deleteApp $appName triggered")
//                if (appName.startsWith("rio-sdk")) {
//                    RioLogger.log("RIOFirebaseManager.deleteApp continuation.resume")
//                    continuation.resume(Unit)
//                }
//            }
//            RioLogger.log("RIOFirebaseManager.deleteApp app.delete() OK $app")
//            it.delete()
//        }
//    }

    private suspend fun initApp(fireInfo: RioFirebase, signIn: Boolean) =
        suspendCoroutine<Unit> { continuation ->
            RioLogger.log("RIOFirebaseManager.initApp called")

            RioLogger.log("RIOFirebaseManager.initApp fireInfo: ${Gson().toJson(fireInfo)}")

            val appState = runCatching {
                app = FirebaseApp.getInstance("rio-sdk")
            }

            if (appState.isFailure) {
                app = FirebaseApp.initializeApp(
                    RioConfig.applicationContext, FirebaseOptions.Builder()
                        .setProjectId(fireInfo.projectId!!)
                        .setApplicationId(fireInfo.envs!!.androidAppId!!)
                        .setGcmSenderId(fireInfo.envs.gcmSenderId!!)
                        .setApiKey(fireInfo.apiKey!!)
                        .build(), "rio-sdk"
                )
            }

            auth = FirebaseAuth.getInstance(app!!)

            RioLogger.log("RIOFirebaseManager.initApp instance created $app")

            if (signIn || appState.isFailure) {
                RioLogger.log("RIOFirebaseManager.initApp currentUser is null")

                auth?.signInWithCustomToken(fireInfo.customToken!!)
                    ?.addOnCompleteListener { task ->
                        RioLogger.log("RIOFirebaseManager.initApp addOnCompleteListener isSuccessful: ${task.isSuccessful}")
                        if (task.isSuccessful) {
                            RioLogger.log("RIOFirebaseManager.authenticate signInWithCustomToken OK")
                        } else {
                            RioLogger.log("RIOFirebaseManager.authenticate addOnCompleteListener message: ${task.exception?.message}")
                        }

                        RioLogger.log("RIOFirebaseManager.authenticate waited 1000 ms")

                        continuation.resume(Unit)
                    }
            } else {
                RioLogger.log("RIOFirebaseManager.initApp currentUser is OK")
                continuation.resume(Unit)
            }
        }

    fun signOut() {
        auth?.signOut()
        auth = null
    }

    fun getDocument(path: String): DocumentReference? {
        RioLogger.log("RIOFirebaseManager.getDocument called")

        return if (app != null) {
            RioLogger.log("RIOFirebaseManager.getDocument app not null $app")

            val store = FirebaseFirestore.getInstance(app!!)

            store.document(path)
        } else {
            RioLogger.log("RIOFirebaseManager.getDocument app null")

            null
        }
    }

    fun isNotAuthenticated(): Boolean {
        return app == null || auth == null
    }
}