project(ROPChain)

include_directories(${PYTHON_INCLUDE_DIRS})
find_package(PythonLibs 2.7 REQUIRED)

include_directories(${Boost_INCLUDE_DIR})
find_package(Boost COMPONET python REQUIERD)
