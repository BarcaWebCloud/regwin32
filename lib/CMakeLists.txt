add_library(RegWin32 regwin32.cpp)
add_library(${PROJECT_NAME}::RegWin32 ALIAS RegWin32)