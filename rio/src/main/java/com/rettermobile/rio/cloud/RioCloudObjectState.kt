package com.rettermobile.rio.cloud

import com.google.firebase.firestore.DocumentReference
import com.google.firebase.firestore.ListenerRegistration
import com.google.gson.Gson
import com.rettermobile.rio.RioConfig
import com.rettermobile.rio.RioFirebaseManager
import com.rettermobile.rio.RioLogger
import com.rettermobile.rio.util.TokenManager
import kotlinx.coroutines.delay

/**
 * Created by semihozkoroglu on 13.12.2021.
 */
sealed class RioCloudObjectState(params: RioCloudObjectOptions) {

    val classId = params.classId
    val instanceId = params.instanceId

    private var listener: ListenerRegistration? = null
    private var document: DocumentReference? = null

    private var successEvent: ((String?) -> Unit)? = null
    private var errorEvent: ((Throwable?) -> Unit)? = null

    private var path = ""

    init {
        path = "/projects/${RioConfig.projectId}/classes/$classId/instances/$instanceId/"

        if (this is RioCloudUserObjectState) {
            path += "userState/${TokenManager.userId()}"
        } else if (this is RioCloudRoleObjectState) {
            path += "roleState/${TokenManager.userIdentity()}"
        }
    }

    fun subscribe(
        eventFired: ((String?) -> Unit)? = null,
        errorFired: ((Throwable?) -> Unit)? = null
    ) {
        successEvent = eventFired
        errorEvent = errorFired

        retryWithSub()
    }

    private fun retryWithSub(retryCount: Int = 1) {
        RioLogger.log("RioCloudObjectState.retryWithSub retryCount: $retryCount")

        document = RioFirebaseManager.getDocument(path)

        RioLogger.log("RioCloudObjectState.subscribe document $document")

        listener = document?.addSnapshotListener { value, error ->
            RioLogger.log("RioCloudObjectState.subscribe addSnapshotListener error: ${error?.message}")
            RioLogger.log("RioCloudObjectState.subscribe addSnapshotListener value: ${Gson().toJson(value?.data)}")

            if (error != null) {
                if (retryCount > 3) {
                    errorEvent?.invoke(error)
                } else {
                    Thread.sleep((100 * retryCount).toLong())

                    retryWithSub(retryCount + 1)
                }
            } else {
                successEvent?.invoke(Gson().toJson(value?.data))
            }
        }
    }

    fun removeListener() {
        listener?.remove()
    }
}

class RioCloudUserObjectState constructor(p: RioCloudObjectOptions) : RioCloudObjectState(p)

class RioCloudRoleObjectState constructor(p: RioCloudObjectOptions) : RioCloudObjectState(p)

class RioCloudPublicObjectState constructor(p: RioCloudObjectOptions) : RioCloudObjectState(p)