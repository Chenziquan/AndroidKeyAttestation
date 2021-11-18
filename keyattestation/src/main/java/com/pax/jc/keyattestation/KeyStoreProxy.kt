package com.pax.jc.keyattestation

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.pax.jc.androidkeystore.KeyStoreHelper
import java.security.cert.Certificate
import java.security.spec.ECGenParameterSpec
import java.util.*

/**
 * @author JQChen.
 * @date on 11/10/2021.
 */
class KeyStoreProxy private constructor(context: Context) {
    companion object {

        @Volatile
        private var instance: KeyStoreProxy? = null

        fun getInstance(context: Context) = instance ?: synchronized(this) {
            instance ?: KeyStoreProxy(context).also { instance = it }
        }
    }

    private var keyStoreHelper: KeyStoreHelper = KeyStoreHelper.getInstance(context)


    fun isKeyStoreBacked(alias: String): Boolean {
        return keyStoreHelper.isKeyStoreBacked(alias) == true
    }

    fun generateKey(
        algorithm: String, keyGenParameterSpec: KeyGenParameterSpec
    ): Boolean {
        return keyStoreHelper.generateKey(algorithm, keyGenParameterSpec) == true
    }

    fun getCertificateChain(alias: String): Array<Certificate> {
        return keyStoreHelper.getCertificateChain(alias)
    }

    fun getCertificate(alias: String): Certificate? {
        return keyStoreHelper.getCertificate(alias)
    }

    fun deleteKey(alias: String) {
        keyStoreHelper.deleteKey(alias)
    }

}