
#include "jvmti.h"
#include <algorithm>
#include <assert.h>
#include <cassert>
#include <chrono>
#include <cstring>
#include <dirent.h>
#include <dlfcn.h>
#include <iostream>
#include <iterator>
#include <mutex>
#include <optional>
#include <pthread.h>
#include <random>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/types.h>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif
#include <array>
#include <atomic>
#include <ucontext.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <sys/resource.h>

/** maximum size of stack trace arrays */
const int MAX_DEPTH = 1024;

static jvmtiEnv *jvmti;
static JavaVM *jvm;
static JNIEnv *env;

std::mutex threadsMutex;
std::unordered_set<pthread_t> threads;

typedef void (*SigAction)(int, siginfo_t *, void *);
typedef void (*SigHandler)(int);
typedef void (*TimerCallback)(void *);

static SigAction installSignalHandler(int signo, SigAction action,
                                      SigHandler handler = nullptr) {
  struct sigaction sa;
  struct sigaction oldsa;
  sigemptyset(&sa.sa_mask);

  if (handler != nullptr) {
    sa.sa_handler = handler;
    sa.sa_flags = 0;
  } else {
    sa.sa_sigaction = action;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
  }

  sigaction(signo, &sa, &oldsa);
  return oldsa.sa_sigaction;
}

void ensureSuccess(jvmtiError err, const char *msg) {
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "Error in %s: %d", msg, err);
    exit(1);
  }
}

template <class T> class JvmtiDeallocator {
public:
  JvmtiDeallocator() { elem_ = nullptr; }

  ~JvmtiDeallocator() {
    if (elem_ != nullptr) {
      jvmti->Deallocate(reinterpret_cast<unsigned char *>(elem_));
    }
  }

  T *get_addr() { return &elem_; }

  T get() { return elem_; }

private:
  T elem_;
};

pthread_t get_thread_id() {
#if defined(__APPLE__) && defined(__MACH__)
  return pthread_self();
#else
  return (pthread_t)syscall(SYS_gettid);
#endif
}

std::recursive_mutex
    threadToJavaIdMutex; // hold this mutex while working with threadToJavaId
std::unordered_map<pthread_t, jlong> threadToJavaId;

struct ThreadState {
  pthread_t thread;
};

jlong obtainJavaThreadIdViaJava(JNIEnv *env, jthread thread) {
  if (env == nullptr) {
    return -1;
  }
  jclass threadClass = env->FindClass("java/lang/Thread");
  jmethodID getId = env->GetMethodID(threadClass, "getId", "()J");
  jlong id = env->CallLongMethod(thread, getId);
  return id;
}

/** returns the jthread for a given Java thread id or null */
jthread getJThreadForPThread(JNIEnv *env, pthread_t threadId) {
  std::lock_guard<std::recursive_mutex> lock(threadToJavaIdMutex);
  std::vector<jthread> threadVec;
  JvmtiDeallocator<jthread *> threads;
  jint thread_count = 0;
  jvmti->GetAllThreads(&thread_count, threads.get_addr());
  for (int i = 0; i < thread_count; i++) {
    jthread thread = threads.get()[i];
    ThreadState *state;
    jvmti->GetThreadLocalStorage(thread, (void **)&state);
    if (state == nullptr) {
      continue;
    }
    if (state->thread == threadId) {
      return thread;
    }
  }
  return nullptr;
}

std::atomic<bool> shouldStop;

static void sampleLoop();

std::thread samplerThread;

void printAGInfo();

void printAGInfoIfNeeded();

void onAbort() {
  shouldStop = true;
  if (samplerThread.joinable()) {
    samplerThread.join();
  }
}

void OnThreadStart(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread) {
  {
    std::lock_guard<std::recursive_mutex> lock(threadToJavaIdMutex);
    threadToJavaId.emplace(get_thread_id(),
                           obtainJavaThreadIdViaJava(jni_env, thread));
  }
  jvmti_env->SetThreadLocalStorage(
      thread, new ThreadState({(pthread_t)get_thread_id()}));
}

void OnThreadEnd(jvmtiEnv *jvmti_env, JNIEnv *jni_env, jthread thread) {
  std::lock_guard<std::recursive_mutex> lock(threadToJavaIdMutex);
  threadToJavaId.erase(get_thread_id());
  printAGInfoIfNeeded();
}

static void GetJMethodIDs(jclass klass) {
  jint method_count = 0;
  JvmtiDeallocator<jmethodID *> methods;
  jvmti->GetClassMethods(klass, &method_count, methods.get_addr());
}

// AsyncGetCallTrace needs class loading events to be turned on!
static void JNICALL OnClassLoad(jvmtiEnv *jvmti, JNIEnv *jni_env,
                                jthread thread, jclass klass) {}

static void JNICALL OnClassPrepare(jvmtiEnv *jvmti, JNIEnv *jni_env,
                                   jthread thread, jclass klass) {
  // We need to do this to "prime the pump" and get jmethodIDs primed.
  GetJMethodIDs(klass);
}

static void startSamplerThread();

static void JNICALL OnVMInit(jvmtiEnv *jvmti, JNIEnv *jni_env, jthread thread) {
  env = jni_env;
  jint class_count = 0;

  // Get any previously loaded classes that won't have gone through the
  // OnClassPrepare callback to prime the jmethods for AsyncGetCallTrace.
  // else the jmethods are all nullptr. This might still happen if ASGCT is
  // called at the very beginning, while this code is executed. But this is not
  // a problem in the typical use case.
  JvmtiDeallocator<jclass *> classes;
  jvmtiError err = jvmti->GetLoadedClasses(&class_count, classes.get_addr());
  if (err != JVMTI_ERROR_NONE) {
    return;
  }

  // Prime any class already loaded and try to get the jmethodIDs set up.
  jclass *classList = classes.get();
  for (int i = 0; i < class_count; ++i) {
    GetJMethodIDs(classList[i]);
  }

  startSamplerThread();
}

// A copy of the ASGCT data structures.
typedef struct {
  jint lineno;         // line number in the source file
  jmethodID method_id; // method executed in this frame
} ASGCT_CallFrame;

typedef struct {
  JNIEnv *env_id;          // Env where trace was recorded
  jint num_frames;         // number of frames in this trace
  ASGCT_CallFrame *frames; // frames
} ASGCT_CallTrace;

typedef void (*ASGCTType)(ASGCT_CallTrace *, jint, void *);

ASGCTType asgct;

static void signalHandler(int signum, siginfo_t *info, void *ucontext);

static void startSamplerThread() {
  samplerThread = std::thread(sampleLoop);
  installSignalHandler(SIGPROF, signalHandler);
}

static int maxDepth = MAX_DEPTH;
static int printEveryNthBrokenTrace = 1;
static int printEveryNthValidTrace = -1;
static int printStatsEveryNthTrace = 10000;
static int printStatsEveryNthBrokenTrace = 5;
static int sampleIntervalInUs = 1;
static bool excludeWaitRelatedFrames = true;

void printHelp() {
  printf(R"(Usage: -agentpath:libbottom.so=[,options]

Options:

  help
    print this help

  maxDepth=<int> (default: 1024)
    maximum depth of the stack traces to be collected
    has to be smaller than 1024

  printEveryNthBrokenTrace=<int> (default: 1)
    print every Nth broken trace, -1 to disable

  printEveryNthValidTrace=<int> (default: -1)
    print every Nth valid trace, -1 to disable

  printStatsEveryNthTrace=<int> (default: 10000)
    print stats every Nth trace, -1 to disable

  printStatsEveryNthBrokenTrace=<int> (default: 5)
    print stats every Nth broken trace, -1 to disable

  sampleIntervalInUs=<int> (default: 1)
    sample interval in microseconds

  excludeWaitRelatedFrames=<bool> (default: true)
    exclude frames that contains "wait", "park" or "sleep" in the top frame method name
    this should reduce the number of false positives
  )");
}

void parseOptions(char *options) {
  if (options == nullptr) {
    return;
  }

  char *token = strtok(options, ",");
  std::string tokenStr = token;
  while (token != nullptr) {
    if (tokenStr == "help") {
      printHelp();
      continue;
    }
    auto equalsPos = tokenStr.find("=");
    if (equalsPos == std::string::npos) {
      printf("Invalid option: %s\n", tokenStr.c_str());
      printHelp();
      exit(1);
    }
    auto key = tokenStr.substr(0, equalsPos);
    auto value = tokenStr.substr(equalsPos + 1);
    if (key == "maxDepth") {
      maxDepth = std::stoi(value);
    } else if (key == "printEveryNthBrokenTrace") {
      printEveryNthBrokenTrace = std::stoi(value);
    } else if (key == "printEveryNthValidTrace") {
      printEveryNthValidTrace = std::stoi(value);
    } else if (key == "printStatsEveryNthTrace") {
      printStatsEveryNthTrace = std::stoi(value);
    } else if (key == "printStatsEveryNthBrokenTrace") {
      printStatsEveryNthBrokenTrace = std::stoi(value);
    } else if (key == "sampleIntervalInUs") {
      sampleIntervalInUs = std::stoi(value);
    } else if (key == "excludeWaitRelatedFrames") {
      excludeWaitRelatedFrames = value == "true";
    } else {
      printf("Invalid option: %s\n", tokenStr.c_str());
      printHelp();
      exit(1);
    }
    token = strtok(nullptr, ",");
  }
}

static void JNICALL OnVMDeath(jvmtiEnv *jvmti_env, JNIEnv *jni_env) {
  onAbort();
}

extern "C" {

static jint Agent_Initialize(JavaVM *_jvm, char *options, void *reserved) {
  parseOptions(options);
  jvm = _jvm;
  jint res = jvm->GetEnv((void **)&jvmti, JVMTI_VERSION);
  if (res != JNI_OK || jvmti == nullptr) {
    fprintf(stderr, "Error: wrong result of a valid call to GetEnv!\n");
    return JNI_ERR;
  }

  jvmtiError err;
  jvmtiCapabilities caps;
  memset(&caps, 0, sizeof(caps));
  caps.can_get_line_numbers = 1;
  caps.can_get_source_file_name = 1;

  ensureSuccess(jvmti->AddCapabilities(&caps), "AddCapabilities");

  jvmtiEventCallbacks callbacks;
  memset(&callbacks, 0, sizeof(callbacks));
  callbacks.ClassLoad = &OnClassLoad;
  callbacks.VMInit = &OnVMInit;
  callbacks.ClassPrepare = &OnClassPrepare;
  callbacks.VMDeath = &OnVMDeath;
  callbacks.ThreadStart = &OnThreadStart;
  callbacks.ThreadEnd = &OnThreadEnd;
  ensureSuccess(
      jvmti->SetEventCallbacks(&callbacks, sizeof(jvmtiEventCallbacks)),
      "SetEventCallbacks");
  ensureSuccess(jvmti->SetEventNotificationMode(
                    JVMTI_ENABLE, JVMTI_EVENT_CLASS_LOAD, nullptr),
                "class load");
  ensureSuccess(jvmti->SetEventNotificationMode(
                    JVMTI_ENABLE, JVMTI_EVENT_CLASS_PREPARE, nullptr),
                "class prepare");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                                JVMTI_EVENT_VM_INIT, nullptr),
                "vm init");
  ensureSuccess(jvmti->SetEventNotificationMode(JVMTI_ENABLE,
                                                JVMTI_EVENT_VM_DEATH, nullptr),
                "vm death");
  ensureSuccess(jvmti->SetEventNotificationMode(
                    JVMTI_ENABLE, JVMTI_EVENT_THREAD_START, nullptr),
                "thread start");
  ensureSuccess(jvmti->SetEventNotificationMode(
                    JVMTI_ENABLE, JVMTI_EVENT_THREAD_END, nullptr),
                "thread end");

  asgct = reinterpret_cast<ASGCTType>(dlsym(RTLD_DEFAULT, "AsyncGetCallTrace"));
  if (asgct == nullptr) {
    fprintf(stderr, "AsyncGetCallTrace not found.\n");
    return JNI_ERR;
  }

  asgct = reinterpret_cast<ASGCTType>(dlsym(RTLD_DEFAULT, "AsyncGetCallTrace"));
  if (asgct == nullptr) {
    fprintf(stderr, "AsyncGetCallTrace not found.\n");
    return JNI_ERR;
  }
  return JNI_OK;
}

JNIEXPORT
jint JNICALL Agent_OnLoad(JavaVM *jvm, char *options, void *reserved) {
  return Agent_Initialize(jvm, options, reserved);
}

JNIEXPORT
jint JNICALL Agent_OnAttach(JavaVM *jvm, char *options, void *reserved) {
  return Agent_Initialize(jvm, options, reserved);
}
}

void printMethod(FILE *stream, jmethodID method) {
  JvmtiDeallocator<char *> name;
  JvmtiDeallocator<char *> signature;
  if (method == nullptr) {
    fprintf(stream, "<null>");
    return;
  }
  jvmtiError err = jvmti->GetMethodName(method, name.get_addr(),
                                        signature.get_addr(), nullptr);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "<err>");
    return;
  }
  jclass klass;
  JvmtiDeallocator<char *> className;
  jvmti->GetMethodDeclaringClass(method, &klass);
  if (klass == nullptr) {
    fprintf(stream, "<err>");
    return;
  }
  jvmti->GetClassSignature(klass, className.get_addr(), nullptr);
  if (className.get() == nullptr) {
    fprintf(stream, "<err>");
    return;
  }
  fprintf(stream, "%s.%s%s", className.get(), name.get(), signature.get());
}

std::string classAndMethodName(jmethodID method) {
  JvmtiDeallocator<char *> name;
  JvmtiDeallocator<char *> signature;
  if (method == nullptr) {
    return "<null>";
  }
  jvmtiError err = jvmti->GetMethodName(method, name.get_addr(),
                                        signature.get_addr(), nullptr);
  if (err != JVMTI_ERROR_NONE) {
    return "<err>";
  }
  jclass klass;
  JvmtiDeallocator<char *> className;
  jvmti->GetMethodDeclaringClass(method, &klass);
  if (klass == nullptr) {
    return "<err>";
  }
  jvmti->GetClassSignature(klass, className.get_addr(), nullptr);
  if (className.get() == nullptr) {
    return "<err>";
  }
  return std::string(className.get()) + "." + name.get() + signature.get();
}

bool areJMethodsEqual(jmethodID first, jmethodID second) {
  std::string firstStr = classAndMethodName(first);
  std::string secondStr = classAndMethodName(second);
  if (firstStr == "<err>" || secondStr == "<err>") {
    return false;
  }
  return firstStr == secondStr;
}

bool areJMethodsUnequal(jmethodID first, jmethodID second) {
  std::string firstStr = classAndMethodName(first);
  std::string secondStr = classAndMethodName(second);
  if (firstStr == "<err>" || secondStr == "<err>") {
    return false;
  }
  return firstStr != secondStr;
}

void printGSTFrame(FILE *stream, jvmtiFrameInfo frame) {
  if (frame.location == -1) {
    fprintf(stream, "Native frame");
    printMethod(stream, frame.method);
  } else {
    fprintf(stream, "Java frame   ");
    printMethod(stream, frame.method);
    fprintf(stream, ": %d", (int)frame.location);
  }
}

void printGSTTrace(FILE *stream, jvmtiFrameInfo *frames, int length) {
  fprintf(stream, "GST Trace length: %d\n", length);
  for (int i = 0; i < length; i++) {
    fprintf(stream, "Frame %d: ", i);
    printGSTFrame(stream, frames[i]);
    fprintf(stream, "\n");
  }
  fprintf(stream, "GST Trace end\n");
}

bool isASGCTNativeFrame(ASGCT_CallFrame frame) { return frame.lineno == -3; }
bool isGSTNativeFrame(jvmtiFrameInfo frame) { return frame.location == -1; }

void printASGCTFrame(FILE *stream, ASGCT_CallFrame frame) {
  JvmtiDeallocator<char *> name;
  if (frame.method_id == nullptr) {
    fprintf(stream, "<null>");
    return;
  }
  jvmtiError err =
      jvmti->GetMethodName(frame.method_id, name.get_addr(), nullptr, nullptr);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stream, "<err %p>", frame.method_id);
    return;
  }
  if (isASGCTNativeFrame(frame)) {
    fprintf(stream, "Native frame ");
    printMethod(stream, frame.method_id);
  } else {
    fprintf(stream, "Java frame   ");
    printMethod(stream, frame.method_id);
    fprintf(stream, ": %d", frame.lineno);
  }
}

void printASGCTFrames(FILE *stream, ASGCT_CallFrame *frames, int length) {
  for (int i = 0; i < length; i++) {
    fprintf(stream, "Frame %d: ", i);
    printASGCTFrame(stream, frames[i]);
    fprintf(stream, "\n");
  }
}

void printASGCTTrace(FILE *stream, ASGCT_CallTrace trace) {
  fprintf(stream, "ASGCT Trace length: %d\n", trace.num_frames);
  if (trace.num_frames > 0) {
    printASGCTFrames(stream, trace.frames, trace.num_frames);
  }
  fprintf(stream, "ASGCT Trace end\n");
}

void printValue(const char *name, std::atomic<size_t> &value,
                std::atomic<size_t> &total) {
  fprintf(stdout, "%-26s: %10ld %10.3f%%\n", name, value.load(),
          value.load() * 100.0 / total.load());
}

JNIEXPORT
void JNICALL Agent_OnUnload(JavaVM *jvm) { onAbort(); }

bool doesFrameEqual(ASGCT_CallFrame frame, const char *className,
                    const char *methodName = nullptr) {
  JvmtiDeallocator<char *> name;
  if (frame.method_id == nullptr) {
    return false;
  }
  jvmtiError err =
      jvmti->GetMethodName(frame.method_id, name.get_addr(), nullptr, nullptr);
  if (err != JVMTI_ERROR_NONE) {
    fprintf(stderr, "=== asgst sampler failed: Error in GetMethodName: %d",
            err);
    return false;
  }
  if (methodName != nullptr && strcmp(name.get(), methodName) != 0) {
    return false;
  }
  jclass klass;
  JvmtiDeallocator<char *> klassName;
  jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
  if (klass == nullptr) {
    return false;
  }
  jvmti->GetClassSignature(klass, klassName.get_addr(), nullptr);
  if (klassName.get() == nullptr) {
    return false;
  }
  if (strncmp(klassName.get(), className, strlen(className)) == 0) {
    return true;
  }
  return false;
}

/** 
 * does frame contain the className and any of the method names (if non-empty)
 */
template <size_t N>
bool doesFrameContain(ASGCT_CallFrame frame, const char *className = nullptr,
                      std::array<const char *, N> methodNames = {}) {
  JvmtiDeallocator<char *> name;
  if (frame.method_id == nullptr) {
    return false;
  }
  jvmtiError err =
      jvmti->GetMethodName(frame.method_id, name.get_addr(), nullptr, nullptr);
  if (err != JVMTI_ERROR_NONE) {
    return false;
  }
  std::string nameStr(name.get());
  if (!methodNames.empty() &&
      std::all_of(methodNames.begin(), methodNames.end(),
                  [&](const char *methodName) {
                    return nameStr.find(methodName) == std::string::npos;
                  })) {
    return false;
  }
  if (className == nullptr) {
    return true;
  }
  jclass klass;
  JvmtiDeallocator<char *> klassName;
  jvmti->GetMethodDeclaringClass(frame.method_id, &klass);
  if (klass == nullptr) {
    return false;
  }
  jvmti->GetClassSignature(klass, klassName.get_addr(), nullptr);
  if (klassName.get() == nullptr) {
    return false;
  }
  if (std::string(klassName.get()).find(className) == std::string::npos) {
    return false;
  }
  return true;
}

bool doesTraceHaveBottomClass(ASGCT_CallTrace &trace, const char *className) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[trace.num_frames - 1];
    return doesFrameEqual(frame, className);
  }
  return false;
}

bool doesTraceHaveFrameSomewhere(ASGCT_CallTrace &trace, const char *className,
                                 const char *methodName = nullptr) {
  for (int i = 0; i < trace.num_frames; i++) {
    ASGCT_CallFrame frame = trace.frames[i];
    return doesFrameEqual(frame, className, methodName);
  }
  return false;
}

bool doesTraceHaveTopFrame(ASGCT_CallTrace &trace, const char *className,
                           const char *methodName) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[0];
    return doesFrameEqual(frame, className, methodName);
  }
  return false;
}

template <size_t N>
bool doesTopFrameContain(ASGCT_CallTrace &trace,
                         const char *className = nullptr,
                         std::array<const char *, N> methodNames = {}) {
  if (trace.num_frames > 0) {
    ASGCT_CallFrame frame = trace.frames[0];
    return doesFrameContain(frame, className, methodNames);
  }
  return false;
}

/** returns true if successful */
bool sendSignal(pthread_t thread) {
  return pthread_kill(thread, SIGPROF) == 0;
}

std::atomic<bool> asgctGSTInSignal;
std::atomic<bool> directlyBeforeGST;
ASGCT_CallTrace agTrace;
ASGCT_CallFrame agFrames[MAX_DEPTH];

std::atomic<size_t> agCheckedTraces(0);
std::atomic<size_t> agBrokenTraces(0);
std::atomic<size_t> agBrokenClassLoaderRelatedTraces(0);
std::atomic<size_t>
    agBrokenAndGSTFarLargerTraces(0); // GST has more than double the number of
std::atomic<size_t> agBrokenBottomMostFrameDifferent(0);

/** idle wait till the atomic variable is as expected or the timeout is reached,
 * returns the value of the atomic variable */
bool waitOnAtomic(std::atomic<bool> &atomic, bool expected = true,
                  int timeout = 100) {
  auto start = std::chrono::system_clock::now();
  while (atomic.load() != expected && std::chrono::system_clock::now() - start <
                                          std::chrono::milliseconds(timeout)) {
  }
  return atomic;
}

void printAGInfo() {
  printValue("agCheckedTraces", agCheckedTraces, agCheckedTraces);
  printValue("  broken", agBrokenTraces, agCheckedTraces);
  printValue("    bottom frame differs", agBrokenBottomMostFrameDifferent,
             agBrokenTraces);
  printValue("    of all: classloader", agBrokenClassLoaderRelatedTraces,
             agBrokenTraces);
  printValue("    of all: far larger", agBrokenAndGSTFarLargerTraces,
             agBrokenTraces);
}

std::atomic<size_t> agLastInfoPrinted(0);

void printAGInfoIfNeeded() {
  if (agLastInfoPrinted.load() != agCheckedTraces.load()) {
    printAGInfo();
    agLastInfoPrinted = agCheckedTraces.load();
  }
}

std::optional<jthread> getAliveJThread(pthread_t thread) {
  jthread javaThread = getJThreadForPThread(env, thread);
  if (javaThread == nullptr) {
    return {};
  }
  jint state;
  jvmti->GetThreadState(javaThread, &state);
  if (!((state & JVMTI_THREAD_STATE_ALIVE) == 1 &&
        (state & JVMTI_THREAD_STATE_RUNNABLE) == 1) &&
      (state & JVMTI_THREAD_STATE_IN_NATIVE) == 0) {
    return {};
  }
  return javaThread;
}

bool isMethodOfValidTrace(jmethodID method) {
  JvmtiDeallocator<char *> name;
  if (method == nullptr) {
    return false;
  }
  if (jvmti->GetMethodName(method, name.get_addr(), nullptr, nullptr) !=
      JVMTI_ERROR_NONE) {
    return false;
  }
  std::string nameStr(name.get());
  for (auto &s : {"wait", "start0", "park", "Wait", "sleep", "sleep0"}) {
    if (nameStr.find(s) == 0 ||
        nameStr.find(s) == nameStr.size() - strlen(s)) { // starts or ends with
      return false;
    }
  }
  return true;
}

bool isValidTrace(ASGCT_CallTrace &trace) {
  return isMethodOfValidTrace(trace.frames[0].method_id);
}

bool isValidTrace(jvmtiFrameInfo frame) {
  return isMethodOfValidTrace(frame.method);
}

/** returns true if the obtaining of stack traces was successful */
bool checkASGCTWithGST(pthread_t thread, jthread javaThread) {

  // reset and init stuff
  asgctGSTInSignal = false;
  directlyBeforeGST = false;
  agTrace.frames = agFrames;
  agTrace.env_id = env;
  // send the signal
  if (!sendSignal(thread)) {
    fprintf(stderr, "could not send signal to thread %ld\n", thread);
    return false;
  }
  // wait for the signal handler to be called
  if (!waitOnAtomic(asgctGSTInSignal)) {
    directlyBeforeGST = true;
    return false;
  }
  // now we know that the signal handler executes it body
  // in theory, it is not possible now to get a stack trace with GST
  jvmtiFrameInfo gstFrames[MAX_DEPTH];
  jint gstCount = 0;
  directlyBeforeGST = true;

  jvmtiError err =
      jvmti->GetStackTrace(javaThread, 0, maxDepth, gstFrames, &gstCount);

  if (err != JVMTI_ERROR_NONE) {
    return false;
  }
  if (gstCount < 1) {
    return false;
  }
  if (agTrace.num_frames < 1) {
    return false;
  }
  if (waitOnAtomic(asgctGSTInSignal, false)) {
    return false;
  }
  if (excludeWaitRelatedFrames &&
      (!isValidTrace(agTrace) || !isValidTrace(gstFrames[0]))) {
    return false;
  }
  if (agTrace.num_frames == MAX_DEPTH || gstCount == MAX_DEPTH) {
    // stacks too deep
    return false;
  }

  // check that gst returned the common part of asgct and asgct2
  int minFrameNum =
      std::min({agTrace.num_frames, gstCount /*, agTrace2.num_frames*/});

  auto print = [&](bool correct, const char *msg = nullptr) {
    if (!correct) {
      agBrokenTraces++;
    }
    if ((correct && printEveryNthValidTrace > 0 &&
         agCheckedTraces % printEveryNthValidTrace == 0) ||
        (!correct && printEveryNthBrokenTrace > 0 &&
         agBrokenTraces % printEveryNthBrokenTrace == 0)) {
      if (msg != nullptr) {
        fprintf(stderr, "%s\n", msg);
      }
      printASGCTTrace(stderr, agTrace);
      printGSTTrace(stderr, gstFrames, gstCount);
    }
    if (!correct) {
      if (doesTraceHaveBottomClass(agTrace, "java/lang/ClassLoader")) {
        agBrokenClassLoaderRelatedTraces++;
      }
      if (minFrameNum < gstCount / 2) {
        agBrokenAndGSTFarLargerTraces++;
      }
    }
    if ((printStatsEveryNthTrace > 0 &&
         agCheckedTraces % printStatsEveryNthTrace == 0) ||
        (!correct && printStatsEveryNthBrokenTrace > 0 &&
         agBrokenTraces % printStatsEveryNthBrokenTrace == 0)) {
      printAGInfo();
    }
  };

  agCheckedTraces++;

  // compare the bottom most frames first
  ASGCT_CallFrame agFrame = agTrace.frames[agTrace.num_frames - 1];
  jvmtiFrameInfo gstFrame = gstFrames[gstCount - 1];

  if (areJMethodsUnequal(agFrame.method_id, gstFrame.method)) {
    // we ignore traces with Unsafe here, as Unsafe.park might be called
    agBrokenBottomMostFrameDifferent++;
    print(false, "bottom most frame is different");
    return true;
  }

  print(true);
  return true;
}

void asgctGSTHandler(ucontext_t *ucontext) {
  asgctGSTInSignal = true;
  waitOnAtomic(directlyBeforeGST, true);
  asgct(&agTrace, maxDepth, ucontext);
  asgctGSTInSignal = false;
}

void checkASGCTWithGST(std::mt19937 &g) {
  std::vector<pthread_t> avThreads;
  {
    std::lock_guard<std::recursive_mutex> lock(threadToJavaIdMutex);
    for (auto &pair : threadToJavaId) {
      avThreads.push_back(pair.first);
    }
  }
  if (avThreads.empty()) {
    return;
  }
  std::shuffle(avThreads.begin(), avThreads.end(), g);
  for (auto thread : avThreads) {
    auto javaThread = getAliveJThread(thread);
    if (!javaThread || !checkASGCTWithGST(thread, *javaThread)) {
      continue;
    }
  }
}

void signalHandler(int signum, siginfo_t *info, void *ucontext) {
  asgctGSTHandler((ucontext_t *)ucontext);
}

void sampleLoop() {
  std::random_device rd;
  std::mt19937 g(rd());
  JNIEnv *newEnv;
  jvm->AttachCurrentThreadAsDaemon(
      (void **)&newEnv,
      nullptr); // important, so that the thread doesn't keep the JVM alive

  if (setpriority(PRIO_PROCESS, 0, 0) != 0) {
    std::cout << "Failed to setpriority: " << std::strerror(errno) << '\n';
  }

  std::chrono::microseconds interval{sampleIntervalInUs};
  while (!shouldStop) {
    if (env == nullptr) {
      env = newEnv;
    }
    auto start = std::chrono::system_clock::now();
    checkASGCTWithGST(g);
    auto duration = std::chrono::system_clock::now() - start;
    auto sleep = interval - duration;
    if (std::chrono::seconds::zero() < sleep) {
      std::this_thread::sleep_for(sleep);
    }
  }
}
