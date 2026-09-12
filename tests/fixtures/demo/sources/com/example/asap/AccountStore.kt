package com.example.asap

// Static review fixture only. These are not functioning application operations.
class AccountStore {
    fun persist(accessToken: String) {
        val prefs = getSharedPreferences("account", MODE_PRIVATE)
        prefs.edit().putString("access_token", accessToken)
        Timber.d("saved token=$accessToken")
    }

    fun configureLogging() {
        interceptor.setLevel(HttpLoggingInterceptor.Level.BODY)
    }
}
