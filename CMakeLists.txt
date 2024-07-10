cmake_minimum_required (VERSION 3.8)
project(RedProxy.Server CXX)

set(CMAKE_CXX_STANDARD 17)

# Create a variable with a list of all source files in the directory 
# and its subdirectories
file(GLOB_RECURSE _SOURCES
	"${CMAKE_CURRENT_SOURCE_DIR}/Source/*.cpp"  
	"${CMAKE_CURRENT_SOURCE_DIR}/Source/*.h"
	"${CMAKE_CURRENT_SOURCE_DIR}/Source/*.ini")
	
add_definitions(-D_WIN32_WINNT=0x0602) # win8 or higher, for boost.log

# Include both source and headers in the files tab in Visual Studio
source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${_SOURCES})
	
set(Boost_USE_STATIC_LIBS 		ON) # find only static libs
set(Boost_USE_MULTITHREADED 	ON)
set(Boost_USE_STATIC_RUNTIME 	OFF)

# Looking for boot library
find_package(Boost REQUIRED COMPONENTS log program_options REQUIRED) 

# Build application
include_directories(${Boost_INCLUDE_DIR})
include_directories("${CMAKE_CURRENT_SOURCE_DIR}/Source")

add_executable(${CMAKE_PROJECT_NAME} ${_SOURCES})
target_link_libraries(${CMAKE_PROJECT_NAME} ${Boost_LIBRARIES} 
	${Boost_LOG_LIBRARY})