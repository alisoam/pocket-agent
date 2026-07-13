package com.example.pocketsshagent.termux

import android.content.Context
import android.util.Log

object TermuxIdentity {
    private const val TAG = "TermuxIdentity"
    private val ALLOWED_PACKAGES = setOf(
        "com.termux",
        "com.termux.api",
    )

    fun isCallerTermux(context: Context, callingUid: Int): Boolean {
        val packages = try {
            context.packageManager.getPackagesForUid(callingUid)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to resolve uid $callingUid", e)
            null
        } ?: return false

        val match = packages.any { it in ALLOWED_PACKAGES }
        if (!match) {
            Log.w(TAG, "Rejected non-Termux caller: uid=$callingUid packages=${packages.toList()}")
        }
        return match
    }
}
