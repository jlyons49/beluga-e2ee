package com.beluga.e2ee.qr

import android.content.Context
import android.net.Uri
import androidx.camera.core.Camera
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.ImageProxy
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.core.content.ContextCompat
import androidx.lifecycle.LifecycleOwner
import com.google.mlkit.vision.barcode.BarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.common.InputImage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Wraps CameraX Preview + ML Kit barcode scanning.
 *
 * Calls onResult with the raw JSON string on the first successful QR decode.
 * Subsequent frames are ignored after the first result (debounced).
 * Call reset() to scan a new code without restarting the camera.
 *
 * Replaces Python's cameraCapture() / pyzbar loop.
 */
class QrScannerHelper(
    private val context: Context,
    private val lifecycleOwner: LifecycleOwner,
    private val previewView: PreviewView,
    private val onResult: (String) -> Unit,
    private val onError: (Exception) -> Unit = {}
) {

    private val executor: ExecutorService = Executors.newSingleThreadExecutor()
    @Volatile private var hasResult = false
    private var camera: Camera? = null

    fun start() {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        providerFuture.addListener({
            val cameraProvider = providerFuture.get()
            bindUseCases(cameraProvider)
        }, ContextCompat.getMainExecutor(context))
    }

    private fun bindUseCases(cameraProvider: ProcessCameraProvider) {
        val preview = Preview.Builder().build().also {
            it.setSurfaceProvider(previewView.surfaceProvider)
        }

        val imageAnalysis = ImageAnalysis.Builder()
            .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
            .build()
            .also { it.setAnalyzer(executor, BarcodeAnalyzer()) }

        try {
            cameraProvider.unbindAll()
            camera = cameraProvider.bindToLifecycle(
                lifecycleOwner,
                CameraSelector.DEFAULT_BACK_CAMERA,
                preview,
                imageAnalysis
            )
        } catch (e: Exception) {
            onError(e)
        }
    }

    /** Allows the next QR code to be scanned after a result was already delivered. */
    fun reset() {
        hasResult = false
    }

    fun stop() {
        executor.shutdown()
    }

    companion object {
        /**
         * Decodes a QR code from a gallery/file URI without using the camera.
         * No storage permission is required — the URI is obtained via the system picker.
         */
        fun scanFromUri(
            context: Context,
            uri: Uri,
            onResult: (String) -> Unit,
            onFailure: (Exception) -> Unit
        ) {
            val image = try {
                InputImage.fromFilePath(context, uri)
            } catch (e: Exception) {
                onFailure(e)
                return
            }
            BarcodeScanning.getClient()
                .process(image)
                .addOnSuccessListener { barcodes ->
                    val raw = barcodes.firstOrNull { it.format == Barcode.FORMAT_QR_CODE }?.rawValue
                    if (raw != null) onResult(raw)
                    else onFailure(Exception("No QR code found in image"))
                }
                .addOnFailureListener { onFailure(it) }
        }
    }

    @androidx.camera.core.ExperimentalGetImage
    private inner class BarcodeAnalyzer : ImageAnalysis.Analyzer {
        private val scanner = BarcodeScanning.getClient()

        override fun analyze(imageProxy: ImageProxy) {
            if (hasResult) {
                imageProxy.close()
                return
            }
            val mediaImage = imageProxy.image
            if (mediaImage == null) {
                imageProxy.close()
                return
            }
            val image = InputImage.fromMediaImage(
                mediaImage,
                imageProxy.imageInfo.rotationDegrees
            )
            scanner.process(image)
                .addOnSuccessListener { barcodes ->
                    barcodes
                        .firstOrNull { it.format == Barcode.FORMAT_QR_CODE }
                        ?.rawValue
                        ?.let { raw ->
                            if (!hasResult) {
                                hasResult = true
                                onResult(raw)
                            }
                        }
                }
                .addOnFailureListener { e -> onError(e) }
                .addOnCompleteListener { imageProxy.close() }
        }
    }
}
