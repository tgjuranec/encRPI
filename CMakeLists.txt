cmake_minimum_required (VERSION 3.6)

#SET CROSS COMPILATION
option(CROSS_COMPILATION_ARM "Compile for arm processor" ON)

if(CROSS_COMPILATION_ARM)

	set(CMAKE_SYSTEM_NAME               Linux)
	set(CMAKE_SYSTEM_PROCESSOR          arm)
	####SYSROOT#### RPI's MOUNTED ROOT IMAGE
	set(RPI_SYSROOT /home/linuser/qemu_vms/mnt)
	set(CMAKE_SYSROOT ${RPI_SYSROOT})
	#TOOLCHAIN FOR RASPBERRY PI 
	#https://github.com/Pro/raspi-toolchain
	set(tooldir /opt/cross-pi-gcc/bin)

	set(CMAKE_AR                        ${tooldir}/arm-linux-gnueabihf-ar)
	set(CMAKE_ASM_COMPILER              ${tooldir}/arm-linux-gnueabihf-as)
	set(CMAKE_C_COMPILER                ${tooldir}/arm-linux-gnueabihf-gcc)
	set(CMAKE_CXX_COMPILER              ${tooldir}/arm-linux-gnueabihf-g++)
	set(CMAKE_LINKER                    ${tooldir}/arm-linux-gnueabihf-gcc)
	set(CMAKE_OBJCOPY                   ${tooldir}/arm-linux-gnueabihf-objcopy)
	set(CMAKE_RANLIB                    ${tooldir}/arm-linux-gnueabihf-ranlib)
	set(CMAKE_SIZE                      ${tooldir}/arm-linux-gnueabihf-size)
	set(CMAKE_STRIP                     ${tooldir}/arm-linux-gnueabihf-strip)
	
	
	set(CMAKE_C_FLAGS_DEBUG             "-g -ggdb --verbose")
	set(CMAKE_C_FLAGS_RELEASE           "-Os -DNDEBUG")
	set(CMAKE_CXX_FLAGS_DEBUG           "${CMAKE_C_FLAGS_DEBUG}")
	set(CMAKE_CXX_FLAGS_RELEASE         "${CMAKE_C_FLAGS_RELEASE}")
	set(CMAKE_C_FLAGS                   ${CMAKE_C_FLAGS_DEBUG})
	#set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} "-mfpu=vfp --with-float-abi=hard" )
	set(CMAKE_CXX_FLAGS                 )
	set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS})
	set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
	set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
	set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE NEVER)
	
	#IMPORTANT!!!! SOME SOFT LINKS IN LIBRARY DIRS ARE BROKEN!!!! 
	#i.e. /usr/lib/arm-linux-gnueabigh/libpthread.so is broken
	#linker wrongly uses libpthread.a -> lots of undefined reference errors!!!!
	#TAKE SOFT LINKS IN SYSROOT AND LINKED DIRS IN ACCOUNT!!!!!
	link_directories(${RPI_SYSROOT}/usr/lib/arm-linux-gnueabihf)
	link_directories(${RPI_SYSROOT}/lib/arm-linux-gnueabihf)
	link_directories(${CMAKE_SYSROOT}/lib)
	link_directories(${CMAKE_SYSROOT}/usr/lib)
	include_directories(/home/linuser/download_source/openssl/include)
endif()

set(SOURCES enc.cpp sslfunc.c)

#####CHECK ALL LIBRARY DIRS#########
get_property(dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY LINK_DIRECTORIES)
foreach(dir ${dirs})
  message(STATUS "dir='${dir}'")
endforeach()

project(encCmake C CXX ASM)


# specify the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(encCmake ${SOURCES})

target_link_libraries(encCmake crypto ssl pthread)

