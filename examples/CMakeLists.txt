cmake_minimum_required(VERSION 3.15)
project(${CMAKE_PROJECT_NAME}_examples LANGUAGES CXX)

file(GLOB_RECURSE examples "*.cpp")

foreach(example ${examples})
    get_filename_component(example_name ${example} NAME_WE)
    add_executable(${example_name} ${example})
    target_link_libraries(
        ${example_name} PRIVATE ${CMAKE_PROJECT_NAME} Threads::Threads
    )
endforeach()
