#include <jni.h>
#include <stdint.h>
#include <openssl/crypto.h>
#include "engine.h"
#define JNI(name) Java_org_proxydroid_engine_NativeEngine_##name
static redsocks_engine *engine(jlong handle) { return (redsocks_engine *)(uintptr_t)handle; }
JNIEXPORT jlong JNICALL JNI(nativeCreate)(JNIEnv *env, jclass type) {
    (void)env; (void)type;
    return (jlong)(uintptr_t)redsocks_engine_create();
}
JNIEXPORT jint JNICALL JNI(nativeStart)(JNIEnv *env, jclass type, jlong handle,
    jint config, jint trust, jint cntlm, jint mark, jboolean validate) {
    (void)env; (void)type;
    redsocks_engine_options options = { config, trust, cntlm, (uint32_t)mark };
    return validate ? redsocks_engine_validate(engine(handle), &options) :
        redsocks_engine_start(engine(handle), &options);
}
JNIEXPORT void JNICALL JNI(nativeStop)(JNIEnv *env, jclass type, jlong handle) {
    (void)env; (void)type;
    redsocks_engine_request_stop(engine(handle));
    redsocks_engine_join(engine(handle));
}
JNIEXPORT void JNICALL JNI(nativeDestroy)(JNIEnv *env, jclass type, jlong handle) {
    (void)env; (void)type; redsocks_engine_destroy(engine(handle));
}
JNIEXPORT jint JNICALL JNI(nativeStatus)(JNIEnv *env, jclass type, jlong handle) {
    (void)env; (void)type; return redsocks_engine_get_status(engine(handle));
}
JNIEXPORT jstring JNICALL JNI(nativeDiagnostics)(JNIEnv *env, jclass type, jlong handle) {
    (void)type; char output[512]; redsocks_engine_diagnostics(engine(handle), output, sizeof(output));
    return (*env)->NewStringUTF(env, output);
}
JNIEXPORT jstring JNICALL JNI(nativeBuildInfo)(JNIEnv *env, jclass type) {
    (void)type; return (*env)->NewStringUTF(env, redsocks_engine_build_info());
}
JNIEXPORT jstring JNICALL JNI(nativeHashes)(JNIEnv *env, jclass type, jstring user, jstring domain, jstring password) {
    (void)type;
    if (!user || !domain || !password) return NULL;
    const char *u = (*env)->GetStringUTFChars(env, user, NULL);
    const char *d = u ? (*env)->GetStringUTFChars(env, domain, NULL) : NULL;
    const char *p = d ? (*env)->GetStringUTFChars(env, password, NULL) : NULL;
    char out[256] = {0};
    int result = u && d && p ? redsocks_engine_hashes(u, d, p, out, sizeof(out)) : -1;
    if (u) (*env)->ReleaseStringUTFChars(env, user, u);
    if (d) (*env)->ReleaseStringUTFChars(env, domain, d);
    if (p) (*env)->ReleaseStringUTFChars(env, password, p);
    jstring value = result ? NULL : (*env)->NewStringUTF(env, out);
    OPENSSL_cleanse(out, sizeof(out));
    return value;
}
JNIEXPORT jstring JNICALL JNI(nativeDetect)(JNIEnv *env, jclass type, jlong handle,
    jint config, jint trust, jint cntlm, jint mark, jstring url) {
    (void)type; char output[1024] = {0};
    if (!url) return NULL;
    redsocks_engine_options options = { config, trust, cntlm, (uint32_t)mark };
    const char *u = (*env)->GetStringUTFChars(env, url, NULL);
    int result = u ? redsocks_engine_detect(engine(handle), &options, u, output, sizeof(output)) : -1;
    if (u) (*env)->ReleaseStringUTFChars(env, url, u);
    return result ? NULL : (*env)->NewStringUTF(env, output);
}
