cmake_minimum_required(VERSION 3.20)
project(gigachat)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(OpenSSL REQUIRED)

add_subdirectory(vendor/glfw)

set(SOURCE_FILES
	main.cpp

	vendor/stb/stb_image.h
	vendor/stb/stb_image_write.h
	vendor/stb/stb_image_resize2.h
	vendor/stb/stb_truetype.h
	vendor/stb/stb_ds.h
	
	vendor/imgui/imconfig.h
	vendor/imgui/imgui.cpp
	vendor/imgui/imgui_demo.cpp
	vendor/imgui/imgui_draw.cpp
	vendor/imgui/imgui.h
	vendor/imgui/backends/imgui_impl_glfw.cpp
	vendor/imgui/backends/imgui_impl_glfw.h
	vendor/imgui/backends/imgui_impl_opengl3.cpp
	vendor/imgui/backends/imgui_impl_opengl3.h
	vendor/imgui/backends/imgui_impl_opengl3_loader.h
	vendor/imgui/imgui_internal.h
	vendor/imgui/imgui_tables.cpp
	vendor/imgui/imgui_widgets.cpp
	vendor/imgui/imstb_rectpack.h
	vendor/imgui/imstb_textedit.h
	vendor/imgui/imstb_truetype.h

	vendor/asio/include/asio.hpp
	vendor/asio/include/asio/ts/buffer.hpp
	vendor/asio/include/asio/ts/internet.hpp
)

include_directories(vendor/glfw/include)
include_directories(vendor/stb)
include_directories(vendor/imgui)
include_directories(vendor/asio/include)

add_executable(gigachat ${SOURCE_FILES})

if (UNIX)
	target_link_libraries(gigachat PRIVATE 
		GL
		glfw
		OpenSSL::Crypto
		OpenSSL::SSL
	)
endif(UNIX)

if (MSVC)
	target_link_libraries(gigachat PRIVATE 
		opengl32
		glfw
		OpenSSL::Crypto
		OpenSSL::SSL
	)
endif (MSVC)
