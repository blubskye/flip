CMAKE_MINIMUM_REQUIRED(VERSION 3.5...3.29)
cmake_policy(SET CMP0003 NEW)

# Basic build file to build thread and mutex classes of dlib

PROJECT(dlib)

SET(DLIB_SRC
dlib/stack_trace.cpp
dlib/threads/threaded_object_extension.cpp
dlib/threads/threads_kernel_1.cpp
dlib/threads/threads_kernel_2.cpp
dlib/threads/threads_kernel_shared.cpp
)

INCLUDE_DIRECTORIES(.)
ADD_LIBRARY(dlib ${DLIB_SRC})

IF("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" AND CMAKE_COMPILER_IS_GNUCC)
	SET_TARGET_PROPERTIES(dlib PROPERTIES COMPILE_FLAGS "-fPIC ${COMPILE_FLAGS} -fPIC")
ENDIF("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64" AND CMAKE_COMPILER_IS_GNUCC)
