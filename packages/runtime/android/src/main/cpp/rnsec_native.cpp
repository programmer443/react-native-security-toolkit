// Native probes for the Android security engine.
//
// This layer exists for reads the managed layer cannot perform correctly:
//
//   * Android system properties. `System.getProperty` reads JVM properties, not
//     Android's, and reflecting into `android.os.SystemProperties` is a
//     restricted non-SDK interface. `__system_property_get` is public NDK API
//     and is subject to neither problem.
//
// Everything here must be total: a probe returns "no value" rather than
// throwing, because a security check that crashes the host application is worse
// than one that reports `unknown`.

#include <jni.h>
#include <dlfcn.h>
#include <sys/system_properties.h>
#include <cstring>

extern "C" JNIEXPORT jstring JNICALL
Java_com_rnsecurity_probe_NativeProbes_getSystemProperty(JNIEnv *env, jclass /* clazz */,
                                                         jstring key) {
  if (key == nullptr) {
    return nullptr;
  }

  const char *keyChars = env->GetStringUTFChars(key, nullptr);
  if (keyChars == nullptr) {
    return nullptr;
  }

  char value[PROP_VALUE_MAX + 1];
  std::memset(value, 0, sizeof(value));
  const int length = __system_property_get(keyChars, value);

  env->ReleaseStringUTFChars(key, keyChars);

  if (length <= 0) {
    return nullptr;
  }

  return env->NewStringUTF(value);
}

// Resolves a symbol and reports which shared library actually provides it.
//
// The interesting case is when the answer is surprising: if `open` or `read`
// resolves inside something other than libc, the symbol has been redirected.
// This is a more reliable signal than comparing function prologue bytes, which
// varies by architecture, compiler and Android version, and produces false
// positives on legitimate instrumentation.
//
// Only the raw fact is returned. Deciding whether a given origin is expected is
// the Kotlin detector's job, where it can be unit-tested.
extern "C" JNIEXPORT jstring JNICALL
Java_com_rnsecurity_probe_NativeProbes_getSymbolOrigin(JNIEnv *env, jclass /* clazz */,
                                                       jstring symbol) {
  if (symbol == nullptr) {
    return nullptr;
  }

  const char *name = env->GetStringUTFChars(symbol, nullptr);
  if (name == nullptr) {
    return nullptr;
  }

  void *address = dlsym(RTLD_DEFAULT, name);
  env->ReleaseStringUTFChars(symbol, name);

  if (address == nullptr) {
    return nullptr;
  }

  Dl_info info;
  std::memset(&info, 0, sizeof(info));
  if (dladdr(address, &info) == 0 || info.dli_fname == nullptr) {
    return nullptr;
  }

  return env->NewStringUTF(info.dli_fname);
}

// Reports whether the native library loaded and is callable. Used by the engine
// to decide between a real property probe and one that reports `indeterminate`.
extern "C" JNIEXPORT jboolean JNICALL
Java_com_rnsecurity_probe_NativeProbes_isAvailable(JNIEnv * /* env */, jclass /* clazz */) {
  return JNI_TRUE;
}
