project(ROPChain)

#FIXME
set(RPP_PATH "$(shell pwd)/src/lib/frontend/rp++/rp_script.sh")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS "-Wall -Wextra -fPIC")
set(CMAKE_CXX_MACROS "-DRPP_PATH=\"${RPP_PATH}\"")

#XXX target_complile_options
#XXX target_link_libraries
add_definitions(${CMAKE_CXX_FLAGS})
add_definitions(${CMAKE_CXX_MACROS})

include_directories("${PROJECT_SOURCE_DIR}")

include_directories(${R_SOCKET_INCLUDE_DIRS})
find_package(r_socket REQUIED)

set(COMMON_SOURCES src/lib/)
set(MAIN_SOURCES src/executable/main.cpp)
set(MODULE_SOURCES src/python_module/main.cpp)
add_executable(ropchain ${COMMON_SOURCES} ${MAIN_SOURCES})
add_executable(libropchain ${COMMON_SOURCES} ${MODULE_SOURCES})
target_link_libraries(ropchain)
