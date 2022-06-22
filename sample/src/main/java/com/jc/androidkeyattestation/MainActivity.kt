package com.jc.androidkeyattestation

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.jc.androidkeyattestation.R
import com.jc.keyattestation.KeyAttestation
import java.io.File
import java.io.OutputStreamWriter

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
            val resultMsg = "Model:${Build.MODEL}, $attestationResult"
            val logPath = saveLogToFile(resultMsg)
            showMsg("LogPath:$logPath \n $resultMsg")
        }.start()
    }

    private fun showMsg(resultMsg: String) {
        runOnUiThread { result.text = resultMsg }
    }

    private fun saveLogToFile(resultMsg: String): String {
        val file = File(this.externalCacheDir, "KeyAttestation.log")
        var outputStreamWriter: OutputStreamWriter? = null
        try {
            outputStreamWriter = OutputStreamWriter(file.outputStream(), Charsets.UTF_8)
            outputStreamWriter.write(resultMsg)
            outputStreamWriter.flush()
        } catch (e: Exception) {
            e.printStackTrace()
        } finally {
            outputStreamWriter?.close()
        }
        return file.absolutePath
    }
}