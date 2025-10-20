cmake_minimum_required(VERSION 3.15...4.00)
project(prideful 
	DESCRIPTION "Superior method of NAT traversal"
	LANGUAGES C)
set(SRC ${PROJECT_SOURCE_DIR}/src/main)
set(HDRS ${PROJECT_SOURCE_DIR}/src/include)
set(DEPS ${PROJECT_SOURCE_DIR}/vendors)
add_subdirectory(${DEPS}/ptools ${DEPS}/ptools/build)

add_library(prideful SHARED
		${SRC}/secret.c
                ${SRC}/oubliette.c
                ${SRC}/severain.c
                ${SRC}/keepalive.c)
target_include_directories(prideful PUBLIC ${HDRS})
target_link_libraries(prideful ptools)

add_executable(sample_client examples/pilot.c)
target_include_directories(sample_client PRIVATE ${HDRS})
target_link_libraries(sample_client prideful ptools)
