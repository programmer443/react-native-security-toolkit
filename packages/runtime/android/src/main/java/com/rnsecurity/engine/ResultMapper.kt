package com.rnsecurity.engine

import com.facebook.react.bridge.Arguments
import com.facebook.react.bridge.WritableArray
import com.facebook.react.bridge.WritableMap

/**
 * Converts engine results into React Native bridge values.
 *
 * The JavaScript side re-validates everything produced here rather than trusting
 * it, so this mapper's job is only to be lossless and total — in particular, an
 * unexpected metadata type is dropped rather than throwing mid-serialisation.
 */
internal object ResultMapper {

  fun toWritableMap(result: CheckResult): WritableMap =
    Arguments.createMap().apply {
      putString("id", result.id)
      putString("status", result.status.wireValue())
      putBoolean("detected", result.detected)
      putString("confidence", result.confidence.wireValue())
      putArray("signals", signalsToArray(result.signals))
      result.unavailableReason?.let { putString("unavailableReason", it.wireValue()) }
      result.errorMessage?.let { putString("errorMessage", it) }
      putMap("metadata", metadataToMap(result.metadata))
      putDouble("durationMs", result.durationMs.toDouble())
      putDouble("checkedAtEpochMs", result.checkedAtEpochMs.toDouble())
    }

  private fun signalsToArray(signals: List<SecuritySignal>): WritableArray =
    Arguments.createArray().apply {
      signals.forEach { signal ->
        pushMap(
          Arguments.createMap().apply {
            putString("id", signal.id)
            putString("outcome", signal.outcome.wireValue())
            putBoolean("detected", signal.detected)
            putString("confidence", signal.confidence.wireValue())
            putString("description", signal.description)
            putMap("metadata", metadataToMap(signal.metadata))
          }
        )
      }
    }

  private fun metadataToMap(metadata: Map<String, Any?>): WritableMap =
    Arguments.createMap().apply {
      metadata.forEach { (key, value) -> putAny(this, key, value) }
    }

  private fun putAny(target: WritableMap, key: String, value: Any?) {
    when (value) {
      null -> target.putNull(key)
      is Boolean -> target.putBoolean(key, value)
      is Int -> target.putInt(key, value)
      is Long -> target.putDouble(key, value.toDouble())
      is Double -> target.putDouble(key, value)
      is Float -> target.putDouble(key, value.toDouble())
      is String -> target.putString(key, value)
      is List<*> -> target.putArray(key, listToArray(value))
      is Map<*, *> ->
        target.putMap(
          key,
          Arguments.createMap().apply {
            value.forEach { (nestedKey, nestedValue) ->
              if (nestedKey is String) putAny(this, nestedKey, nestedValue)
            }
          }
        )
      // Anything else is a detector bug rather than a runtime condition; record
      // that it happened instead of silently dropping the key.
      else -> target.putString(key, "<unsupported:${value.javaClass.simpleName}>")
    }
  }

  private fun listToArray(values: List<*>): WritableArray =
    Arguments.createArray().apply {
      values.forEach { value ->
        when (value) {
          null -> pushNull()
          is Boolean -> pushBoolean(value)
          is Int -> pushInt(value)
          is Long -> pushDouble(value.toDouble())
          is Double -> pushDouble(value)
          is Float -> pushDouble(value.toDouble())
          is String -> pushString(value)
          is List<*> -> pushArray(listToArray(value))
          else -> pushString("<unsupported:${value.javaClass.simpleName}>")
        }
      }
    }
}
