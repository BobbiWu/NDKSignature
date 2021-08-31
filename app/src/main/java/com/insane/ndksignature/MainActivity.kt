package com.insane.ndksignature

import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.insane.ndksignature.databinding.ActivityMainBinding
import java.io.UnsupportedEncodingException
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import kotlin.experimental.and

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Example of a call to a native method
//        binding.sampleText.text = getSuccessKeyFromJNI()
        binding.sampleBt.setOnClickListener {

        }
    }

    companion object {
        // Used to load the 'ndksignature' library on application startup.
        init {
            System.loadLibrary("ndksignature")
        }
    }
}