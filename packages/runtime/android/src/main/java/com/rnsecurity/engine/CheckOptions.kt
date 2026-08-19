package com.rnsecurity.engine

/**
 * Per-call configuration supplied by the application.
 *
 * Some checks cannot say anything useful without configuration — integrity has
 * no opinion on a signing certificate until it is told which one to expect.
 * Passing that configuration per call keeps the native engine **stateless**:
 * there is no `configure()` on the native side whose ordering relative to a
 * check could matter, and no chance of a check running against configuration
 * that was replaced halfway through.
 *
 * Reads are total. A missing or wrongly typed value returns `null`, and the
 * detector reports `indeterminate` or `not-configured` rather than guessing.
 */
class CheckOptions(private val values: Map<String, Any?>) {

  fun string(key: String): String? = (values[key] as? String)?.takeIf { it.isNotEmpty() }

  fun stringList(key: String): List<String>? {
    val raw = values[key] as? List<*> ?: return null
    val strings = raw.filterIsInstance<String>().filter { it.isNotEmpty() }
    return strings.ifEmpty { null }
  }

  fun boolean(key: String): Boolean? = values[key] as? Boolean

  companion object {
    val EMPTY = CheckOptions(emptyMap())
  }
}
