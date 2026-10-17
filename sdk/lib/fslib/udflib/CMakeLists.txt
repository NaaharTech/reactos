include_directories(${CMAKE_CURRENT_SOURCE_DIR}/compat ${CMAKE_CURRENT_SOURCE_DIR}/core)
add_library(udflib udflib.c core/udf_create.c core/udf_write.c core/udf_osta.c)
add_dependencies(udflib xdk)
set_source_files_properties(core/udf_create.c PROPERTIES COMPILE_FLAGS "-Wno-address-of-packed-member")
