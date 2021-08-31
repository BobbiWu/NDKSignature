#include <jni.h>
#include <string>
#include <android/log.h>
#include <iostream>
#include "md5.h"
#include "sha1.h"
#include "sha256.h"


#define LOG_TAG  "C_TAG"
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
enum HASH {
    HASH_MD5, HASH_SHA1, HASH_SHA256
};
const char *RELEASE_SIGN = "";


jbyteArray getSignatureByte(JNIEnv *env, jobject context);

void hashByteArray(HASH type, const void *data, size_t numBytes, char *resultData);

void formatSignature(char *data, char *resultData);

// Native 从 Context 中获取签名
jbyteArray getSignatureByte(JNIEnv *env, jobject context) {
    // Context 的类
    jclass context_clazz = env->GetObjectClass(context);
    // 得到 getPackageManager 方法的 ID
    jmethodID methodID_getPackageManager = env->GetMethodID(context_clazz, "getPackageManager",
                                                            "()Landroid/content/pm/PackageManager;");
    // 获得 PackageManager 对象
    jobject packageManager = env->CallObjectMethod(context, methodID_getPackageManager);
    // 获得 PackageManager 类
    jclass packageManager_clazz = env->GetObjectClass(packageManager);
    // 得到 getPackageInfo 方法的 ID
    jmethodID methodID_getPackageInfo = env->GetMethodID(packageManager_clazz, "getPackageInfo",
                                                         "(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;");
    // 得到 getPackageName 方法的 ID
    jmethodID methodID_getPackageName = env->GetMethodID(context_clazz, "getPackageName",
                                                         "()Ljava/lang/String;");
    // 获得当前应用的包名
    jobject application_package_obj = env->CallObjectMethod(context, methodID_getPackageName);
    auto application_package = static_cast<jstring>(application_package_obj);
    // 获得 PackageInfo
    jobject packageInfo = env->CallObjectMethod(packageManager, methodID_getPackageInfo,
                                                application_package, 64);
    jclass packageinfo_clazz = env->GetObjectClass(packageInfo);
    // 获取签名
    jfieldID fieldID_signatures = env->GetFieldID(packageinfo_clazz, "signatures",
                                                  "[Landroid/content/pm/Signature;");
    auto signature_arr = (jobjectArray) env->GetObjectField(packageInfo,
                                                            fieldID_signatures);

    // Signature 数组中取出第一个元素
    jobject signature = env->GetObjectArrayElement(signature_arr, 0);
    // 读 signature 的 ByteArray
    jclass signature_clazz = env->GetObjectClass(signature);
    jmethodID methodID_byteArray = env->GetMethodID(signature_clazz, "toByteArray", "()[B");
    jobject cert_obj = env->CallObjectMethod(signature, methodID_byteArray);
    auto cert_byteArray = static_cast<jbyteArray>(cert_obj);

    return cert_byteArray;
}

// 获得签名的 MD5 SHA1 SHA256
void hashByteArray(HASH type, const void *data, size_t numBytes, char *resultData) {
    if (type == HASH_MD5) {
        MD5 md5;
        std::string md5String = md5(data, numBytes);
        char *tabStr = new char[md5String.length() + 1];
        strcpy(tabStr, md5String.c_str());
        formatSignature(tabStr, resultData);
    } else if (type == HASH_SHA1) {
        SHA1 sha1;
        std::string sha1String = sha1(data, numBytes);
        char *tabStr = new char[sha1String.length() + 1];
        strcpy(tabStr, sha1String.c_str());
        formatSignature(tabStr, resultData);
    } else if (type == HASH_SHA256) {
        SHA256 sha256;
        std::string sha256String = sha256(data, numBytes);
        char *tabStr = new char[sha256String.length() + 1];
        strcpy(tabStr, sha256String.c_str());
        formatSignature(tabStr, resultData);
    }
}

// 格式化输出
void formatSignature(char *data, char *resultData) {
    int resultIndex = 0;
    int length = strlen(data);
    for (int i = 0; i < length; i++) {
        resultData[resultIndex] = static_cast<char>(toupper(data[i]));
        if (i % 2 == 1 && i != length - 1) {
            resultData[resultIndex + 1] = ':';
            resultIndex += 2;
        } else {
            resultIndex++;
        }
    }
}


jboolean checkSignature(JNIEnv *env, jobject context) {
    jbyteArray cert_byteArray = getSignatureByte(env, context);
    jsize size = env->GetArrayLength(cert_byteArray);
    jbyte *jbyteArray = new jbyte[size];
    env->GetByteArrayRegion(cert_byteArray, 0, size, jbyteArray);
    char certMD5[128] = {0};
    hashByteArray(HASH_MD5, jbyteArray, size, certMD5);
    char certSHA1[128] = {0};
    hashByteArray(HASH_SHA1, jbyteArray, size, certSHA1);
    char certSHA256[128] = {0};
    hashByteArray(HASH_SHA256, jbyteArray, size, certSHA256);


    char resultStr[1000] = {0};
    strcat(resultStr, certMD5);
    strcat(resultStr, certSHA1);
    strcat(resultStr, certSHA256);
    jstring appSignature = env->NewStringUTF(resultStr);
    jstring releaseSignature = env->NewStringUTF(RELEASE_SIGN);
    const char *charAppSignature = env->GetStringUTFChars(appSignature, nullptr);
    const char *charReleaseSignature = env->GetStringUTFChars(releaseSignature, nullptr);

    // __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", charAppSignature);
    // __android_log_print(ANDROID_LOG_INFO, LOG_TAG, "%s", RELEASE_SIGN);
    jboolean result = JNI_FALSE;
    // 比较是否相等
    if (charAppSignature != nullptr && charReleaseSignature != nullptr) {
        if (strcmp(charAppSignature, charReleaseSignature) == 0) {
            result = JNI_TRUE;
        }
    }

    env->ReleaseStringUTFChars(appSignature, charAppSignature);
    env->ReleaseStringUTFChars(releaseSignature, charReleaseSignature);

    return result;
}

static jobject getApplication(JNIEnv *env) {
    jobject application = nullptr;
    jclass activity_thread_clz = env->FindClass("android/app/ActivityThread");
    if (activity_thread_clz != nullptr) {
        jmethodID currentApplication = env->GetStaticMethodID(
                activity_thread_clz, "currentApplication", "()Landroid/app/Application;");
        if (currentApplication != nullptr) {
            application = env->CallStaticObjectMethod(activity_thread_clz, currentApplication);
        } else {
            LOGD("Cannot find method: currentApplication() in ActivityThread.");
        }
        env->DeleteLocalRef(activity_thread_clz);
    } else {
        LOGD("Cannot find class: android.app.ActivityThread");
    }

    return application;
}

/**
 * 检查加载该so的应用的签名，与预置的签名是否一致
 */
static jboolean checkSignature(JNIEnv *env) {

    // 调用 getContext 方法得到 Context 对象
    jobject appContext = getApplication(env);

    if (appContext != nullptr) {
        jboolean signatureValid = checkSignature(
                env, appContext);
        return signatureValid;
    }

    return JNI_FALSE;
}

/**
 * 加载 so 文件的时候，会触发 OnLoad
 * 检测失败，返回 -1，App 就会 Crash
 */
JNIEXPORT jint

JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    if (vm->GetEnv((void **) (&env), JNI_VERSION_1_6) != JNI_OK) {
        return -1;
    }
    if (checkSignature(env) != JNI_TRUE) {
        // 检测不通过，返回 -1 就会使 App crash
        return -1;
    }
    return JNI_VERSION_1_6;
}