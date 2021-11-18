package com.pax.jc.androidkeyattestation

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.pax.jc.keyattestation.KeyAttestation

class MainActivity : AppCompatActivity() {
    val keyAttestation = KeyAttestation.getInstance()
    lateinit var result: TextView
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        result = findViewById(R.id.main_tv)
        findViewById<Button>(R.id.main_btn)
            .setOnClickListener { attestation() }
    }

    private fun attestation() {
        Thread {
            val attestationResult = keyAttestation.attestation(this)
            runOnUiThread { result.text = attestationResult.toString() }
        }.start()
    }
}