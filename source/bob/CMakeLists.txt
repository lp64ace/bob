# -----------------------------------------------------------------------------
# Define Include Directories

set(INC
	# Internal Include Directories
	PUBLIC .
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories

set(INC_SYS
	# External System Include Directories
	${PTHREADS_INCLUDE_DIRS}
	
)

# -----------------------------------------------------------------------------
# Define Source Files

set(SRC
	manualmap.h
	remote.h
	
	intern/manualmap.c
	intern/remote.cc

)

# -----------------------------------------------------------------------------
# Define Library Dependencies

set(LIB
	# Internal Library Dependencies
	PUBLIC bob::extern::asmjit
	PUBLIC bob::intern::guardedalloc
	PUBLIC bob::intern::utils
	PUBLIC bob::intern::mom
	
	# External Library Dependencies
	PUBLIC ${PTHREADS_LIBRARIES}
	
)

# -----------------------------------------------------------------------------
# Declare Library

bob_add_lib(bob "${SRC}" "${INC}" "${INC_SYS}" "${LIB}")
add_library(bob::source::bob ALIAS bob)

# -----------------------------------------------------------------------------
# Build Resources

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
	COMMAND
		${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND
		"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:testdll1>" --bin ${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
	DEPENDS
		testdll1
		datatoc
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/testdll2_resource.c
	COMMAND
		${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND
		"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:testdll2>" --bin ${CMAKE_CURRENT_BINARY_DIR}/testdll2_resource.c
	DEPENDS
		testdll2
		datatoc
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/testdll3_resource.c
	COMMAND
		${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND
		"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:testdll3>" --bin ${CMAKE_CURRENT_BINARY_DIR}/testdll3_resource.c
	DEPENDS
		testdll3
		datatoc
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/memalloc_resource.c
	COMMAND
		${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND
		"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:memallocdll>" --bin ${CMAKE_CURRENT_BINARY_DIR}/memalloc_resource.c
	DEPENDS
		memallocdll
		datatoc
)

add_custom_command(
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/xorstrdll_resource.c
	COMMAND
		${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}
	COMMAND
		"$<TARGET_FILE:datatoc>" --src "$<TARGET_FILE:xorstrdll>" --bin ${CMAKE_CURRENT_BINARY_DIR}/xorstrdll_resource.c
	DEPENDS
		xorstrdll
		datatoc
)

# -----------------------------------------------------------------------------
# Define Include Directories (Test)

set(INC
	# Internal Include Directories
	PUBLIC .
	${CMAKE_CURRENT_BINARY_DIR}
	
	# External Include Directories
	
)

# -----------------------------------------------------------------------------
# Define System Include Directories (Test)

set(INC_SYS
	# External System Include Directories
	
)

# -----------------------------------------------------------------------------
# Define Source Files (Test)

set(TEST
	test/manualmap.cc
	
	# Resources
	${CMAKE_CURRENT_BINARY_DIR}/testdll1_resource.c
	${CMAKE_CURRENT_BINARY_DIR}/testdll2_resource.c
	${CMAKE_CURRENT_BINARY_DIR}/testdll3_resource.c
	${CMAKE_CURRENT_BINARY_DIR}/memalloc_resource.c
	${CMAKE_CURRENT_BINARY_DIR}/xorstrdll_resource.c
	
)

# -----------------------------------------------------------------------------
# Define Library Dependencies (Test)

set(LIB
	# Internal Library Dependencies
	bob::source::bob
	
	# External Library Dependencies
	
)

# -----------------------------------------------------------------------------
# Declare Test

bob_add_test_executable(bob "${TEST}" "${INC}" "${INC_SYS}" "${LIB}")

add_dependencies(bob bob::source::testdll1)
add_dependencies(bob bob::source::testdll2)
add_dependencies(bob bob::source::testdll3)
add_dependencies(bob bob::source::memallocdll)
add_dependencies(bob bob::source::xorstrdll)
