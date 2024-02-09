# -------------------------------------------------------------------------------------------------- #
# Copyright (c) 2014 - 2023 by Axel Kenzo, axelkenzo@mail.ru
#
# CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
cmake_minimum_required( VERSION 3.5 )

# -------------------------------------------------------------------------------------------------- #
set( HEAD_VERSION 0 )
set( MAIN_VERSION 9 )
set( MINOR_VERSION 12 )
set( MAJOR_VERSION ${HEAD_VERSION}.${MAIN_VERSION} )
set( FULL_VERSION ${MAJOR_VERSION}.${MINOR_VERSION} )
# строка с текущей датой, используется при сборке документации
string( TIMESTAMP CURRENT_DATE_STRING "[%d %B, %Y]" )

# -------------------------------------------------------------------------------------------------- #
# Формируем название проекта
project( libakrypt C CXX )

# -------------------------------------------------------------------------------------------------- #
# Перечень доступных опций для сборки библиотеки
option( AK_SHARED_LIB "Build the shared library" OFF )
option( AK_STATIC_LIB "Build the static library" ON )
option( AK_EXAMPLES "Build examples for libakrypt" OFF )
option( AK_TESTS "Build tests for libakrypt" OFF )
option( AK_TESTS_GMP "Build comparison tests for gmp and libakrypt" OFF )
string( COMPARE EQUAL ${CMAKE_HOST_SYSTEM_NAME} "FreeBSD" AK_FREEBSD )

# -------------------------------------------------------------------------------------------------- #
# Перечень опций, которые имеют предустановленные значения и могут изменяться через командную строку
# для linux
#   set( AK_CONFIG_PATH  "/etc" )
#   set( AK_CA_PATH "/usr/share/ca-certificates" )

# -------------------------------------------------------------------------------------------------- #
# Определяем базовое множество исходных текстов библиотеки
set( MAIN_HEADERS ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-base.h source/libakrypt.h )

# -------------------------------------------------------------------------------------------------- #
set( AKBASE_SOURCES
   source/ak_tools.c
   source/ak_ini.c
   source/ak_list.c
   source/ak_file.c
   source/ak_buffer.c
   source/ak_base64.c
  )

# -------------------------------------------------------------------------------------------------- #
# Добавляем исходные тексты для криптобиблиотеки
set( AKRYPT_SOURCES
   source/libakrypt-internal.h
   source/cf_operations.c
   source/ak_options.c
   source/ak_libakrypt.c
   source/ak_oid.c
   source/ak_random.c
   source/ak_gf2n.c
   source/ak_mpzn.c
   source/ak_curves.c
   source/ak_parameters.c
   source/ak_mac.c
   source/ak_hash.c
   source/ak_skey.c
   source/ak_hmac.c
   source/ak_bckey.c
   source/ak_cmac.c
   source/ak_magma.c
   source/ak_kuznechik.c
   source/ak_acpkm.c
   source/ak_mgm.c
   source/ak_aead.c
   source/ak_xts.c
   source/ak_xtsmac.c
   source/ak_asn1.c
   source/ak_sign.c
   source/ak_asn1_keys.c
   source/ak_asn1_cert.c
   source/ak_blom.c
   source/ak_kdf.c
   source/ak_encrypt.c
)

# -------------------------------------------------------------------------------------------------- #
# Проверка архитектуры
include( TestBigEndian )
TEST_BIG_ENDIAN( IS_BIG_ENDIAN )
if( IS_BIG_ENDIAN )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_BIG_ENDIAN" )
else()
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_LITTLE_ENDIAN" )
endif()
message("-- Used compile flags ${CMAKE_C_FLAGS}")

# -------------------------------------------------------------------------------------------------- #
# Подключаем модули CMake для тонкой настройки параметров сборки
set( CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake ${CMAKE_MODULE_PATH} )
include( DetectFlags )
include( DetectHeaders )
include( DetectIntrinsics )
include( DetectLibraries )
# модули CMake
include( GNUInstallDirs )

# -------------------------------------------------------------------------------------------------- #
# Вырабатываем заголовочный файл (в каталоге сборки)
configure_file( ${CMAKE_CURRENT_SOURCE_DIR}/source/libakrypt-base.h.in ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-base.h @ONLY )
message("-- Generation of libakrypt-base.h is done")

# -------------------------------------------------------------------------------------------------- #
# Определяем место хранения файла с настройками библиотеки
# -------------------------------------------------------------------------------------------------- #
if( AK_CONFIG_PATH )
else()
  if( CMAKE_HOST_UNIX )
    set( AK_CONFIG_PATH "/etc" )
  endif()
  if( WIN32 )
    set( AK_CONFIG_PATH "C:\\\\Program Files\\\\Akrypt" )
  endif()
endif()
message("-- Path for libakrypt.conf is ${AK_CONFIG_PATH}")

# -------------------------------------------------------------------------------------------------- #
# Определяем место хранения доверенных сертификатов библиотеки
# -------------------------------------------------------------------------------------------------- #
if( AK_CA_PATH )
else()
  if( CMAKE_HOST_UNIX )
    set( AK_CA_PATH ${CMAKE_INSTALL_PREFIX}/share/ca-certificates/libakrypt )
  endif()
  if( WIN32 )
    set( AK_CA_PATH "C:\\\\Program Files\\\\Akrypt\\\\ca-certificates" )
  endif()
endif()
message("-- Path for ca-certificates is ${AK_CA_PATH}")

# -------------------------------------------------------------------------------------------------- #
# Определем процедуры сборки библиотек - статической или динамической
include_directories( "source" )
include_directories( ${CMAKE_CURRENT_BINARY_DIR} )
add_compile_options( -DLIBAKRYPT_OPTIONS_PATH="${AK_CONFIG_PATH}" )
add_compile_options( -DLIBAKRYPT_VERSION="${FULL_VERSION}" )
add_compile_options( -DLIBAKRYPT_COMPILER_NAME="${CMAKE_C_COMPILER_ID}" )
add_compile_options( -DLIBAKRYPT_COMPILER_VERSION="${CMAKE_C_COMPILER_VERSION}" )
add_compile_options( -DLIBAKRYPT_CA_PATH="${AK_CA_PATH}" )
if( CMAKE_HOST_UNIX )
  if( AK_FREEBSD )
    set( AK_LOCALE_PATH "/usr/local/share/locale" )
  else()
    set( AK_LOCALE_PATH "/usr/share/locale" )
  endif()
  add_compile_options( -DLIBAKRYPT_LOCALE_PATH="${AK_LOCALE_PATH}" )
endif()

if( AK_SHARED_LIB )
  add_library( akbase-shared SHARED ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akbase-shared PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akbase-shared ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt-base: shared library" )

  add_library( akrypt-shared SHARED ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
  set_target_properties( akrypt-shared PROPERTIES VERSION ${MAJOR_VERSION} SOVERSION ${FULL_VERSION} )
  set_target_properties( akrypt-shared PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akrypt-shared akbase-shared ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt: shared library" )
endif()

#
if( AK_STATIC_LIB )
  add_library( akbase-static STATIC ${MAIN_HEADERS} ${AKBASE_SOURCES} )
  set_target_properties( akbase-static PROPERTIES OUTPUT_NAME akrypt-base CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akbase-static ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt-base: static library" )

  add_library( akrypt-static STATIC ${MAIN_HEADERS} ${AKRYPT_SOURCES} )
  set_target_properties( akrypt-static PROPERTIES OUTPUT_NAME akrypt CLEAN_DIRECT_CUSTOM 1 )
  target_link_libraries( akrypt-static akbase-static ${LIBAKRYPT_LIBS} )
  message( "-- Building libakrypt: static library" )
endif()

# -------------------------------------------------------------------------------------------------- #
# Сборка различных примеров и иллюстраций
# -------------------------------------------------------------------------------------------------- #
# начинаем с примеров
# определяем перечень примеров и тестов для akbase
set( BASE_EXAMPLES_LIST
     ini
     ini-file
     file
     mmap
     realpath
   )

# определяем перечень примеров из FAQ
set( EXAMPLES_LIST
     g01n01 g01n02 g01n03
     g02n01 g02n02 g02n03 g02n04
     g03n01 g03n02 g03n03 g03n04
     g04n01 g04n02
     g05n01 g05n02 g05n03
   )

if( AK_EXAMPLES )
  message("-- Akbase examples (now \"make test\" enabled):" )
  enable_testing()
  foreach( programm ${BASE_EXAMPLES_LIST} )
    if( AK_STATIC_LIB )
      add_executable( example-${programm} examples/akbase/example-${programm}.c )
      target_link_libraries( example-${programm} akbase-static ${LIBAKRYPT_LIBS} )
      message("      example-${programm}" )
      add_test( NAME example-${programm} COMMAND example-${programm} )
    endif()
    if( AK_SHARED_LIB )
      add_executable( example-shared-${programm} examples/akbase/example-${programm}.c )
      target_link_libraries( example-shared-${programm} akbase-shared ${LIBAKRYPT_LIBS} )
      message("      example-shared-${programm}" )
      add_test( NAME example-shared-${programm} COMMAND example-shared-${programm} )
    endif()
  endforeach()

 # теперь то же самое, но из другого каталога + дополнительные зависимости
  message("-- FAQ examples:" )
  enable_testing()
  foreach( programm ${EXAMPLES_LIST} )
    if( AK_STATIC_LIB )
      add_executable( example-${programm} examples/faq/example-${programm}.c )
      target_link_libraries( example-${programm} akbase-static akrypt-static ${LIBAKRYPT_LIBS} )
      message("      example-${programm}" )
      add_test( NAME example-static-${programm} COMMAND example-${programm} )
    endif()
    if( AK_SHARED_LIB )
      add_executable( example-shared-${programm} examples/faq/example-${programm}.c )
      target_link_libraries( example-shared-${programm} akbase-shared akrypt-shared ${LIBAKRYPT_LIBS} )
      message("      example-shared-${programm}" )
      add_test( NAME example-shared-${programm} COMMAND example-shared-${programm} )
    endif()
  endforeach()
endif()

# -------------------------------------------------------------------------------------------------- #
# теперь тесты (включая арифметические)
if( AK_TESTS_GMP )
  set( AK_TESTS ON )
endif()

set ( ARITHMETIC_TESTS_LIST
      random01
      random02
      gf2n
      mgm01
      xtsmac01
      aead
      asn1-build
      asn1-parse
      sign01
      asn1-keys
      asn1-keys02
      blom-keys
      cmac01
      cmac02
      hmac
      kdf-state
    )

if( AK_TESTS_GMP )
  set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DAK_HAVE_GMP_H" )
  set( ARITHMETIC_TESTS_LIST ${ARITHMETIC_TESTS_LIST}
      mpzn-arithmetic
      mpzn-convert
      mpzn-montgomery
      mpzn-rem
      mpzn-password
     )
endif()

if( AK_TESTS )
  enable_testing()
  message("-- Internal tests (now \"make test\" enabled):" )
  foreach( programm ${ARITHMETIC_TESTS_LIST} )
    add_executable( test-${programm} examples/tests/test-${programm}.c )
    if( AK_STATIC_LIB )
      target_link_libraries( test-${programm} akrypt-static akbase-static ${LIBAKRYPT_LIBS} )
    else()
      target_link_libraries( test-${programm} akrypt-shared akbase-shared ${LIBAKRYPT_LIBS} )
    endif()
    add_test( NAME test-${programm} COMMAND test-${programm} )
    message("      test-${programm}" )
  endforeach()
endif()


# -------------------------------------------------------------------------------------------------- #
# Сборка документации и завершающие настройки
 include( MakeDoc )
 set( LIBAKRYPT_DOCUMENTATION
      ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
      ${CMAKE_CURRENT_SOURCE_DIR}/Changelog.md
 )
 # теперь файлы с документацией не включаются в перечень инсталлируемых файлов по-умолчанию
 # set( LIBAKRYPT_GENERATED_DOCUMENTATION
 #    ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-base-doc-${FULL_VERSION}.pdf
 #    ${CMAKE_CURRENT_BINARY_DIR}/libakrypt-doc-${FULL_VERSION}.pdf
 #   )

# -------------------------------------------------------------------------------------------------- #
# инсталляция библиотеки (только для UNIX)
message("-- Install path:" ${CMAKE_INSTALL_PREFIX} )
if( CMAKE_HOST_UNIX )
  if( AK_STATIC_LIB )
    install( TARGETS akbase-static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
    install( TARGETS akrypt-static LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
  endif()

  if( AK_SHARED_LIB )
    install( TARGETS akbase-shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
    install( TARGETS akrypt-shared LIBRARY DESTINATION lib ARCHIVE DESTINATION lib )
  endif()

 # инсталлируем заголовочные файлы и документацию к библиотеке
  install( FILES ${MAIN_HEADERS} DESTINATION include )
  install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/libakrypt.conf DESTINATION ${AK_CONFIG_PATH} )
  install( FILES ${LIBAKRYPT_DOCUMENTATION} DESTINATION ${CMAKE_INSTALL_FULL_DOCDIR} )

  install( FILES ${CMAKE_CURRENT_SOURCE_DIR}/cert/ca-libakrypt.crt DESTINATION ${AK_CA_PATH} )

# деинсталляция
# sudo xargs rm < install_manifest.txt

endif()

# -------------------------------------------------------------------------------------------------- #
# настройка пакета для дистрибуции
set( CPACK_GENERATOR "DEB" )
set( CPACK_SOURCE_GENERATOR "TBZ2")
set( CPACK_SOURCE_IGNORE_FILES
  \\.git/
  .gitignore
  .delme*
  .kdev4/*
  TAGS
  "CMakeLists.txt.user*"
  "scratch*"
)

# в зависимостях можно указать в явном виде стандартную библиотеку языка Си,
# но она и так входит в перечень
set( CPACK_DEBIAN_PACKAGE_DEPENDS "libbz2-1.0" )
set( CPACK_PACKAGE_VERSION_MAJOR ${HEAD_VERSION} )
set( CPACK_PACKAGE_VERSION_MINOR ${MAIN_VERSION} )
set( CPACK_PACKAGE_VERSION_PATCH ${MINOR_VERSION} )

set( CPACK_DEBIAN_PACKAGE_MAINTAINER "Axel Kenzo") #required
set( CPACK_PACKAGE_VENDOR "Axel Kenzo и Компания изящной словесности")
set( CPACK_PACKAGE_FILE_NAME ${CMAKE_PROJECT_NAME}-${FULL_VERSION}-${CMAKE_SYSTEM_PROCESSOR} )
set( CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME}-${FULL_VERSION}" )
set( CPACK_STRIP_FILES TRUE )
set( CPACK_PACKAGE_DESCRIPTION
     "Библиотека, реализующая российские криптографические механизмы в пространстве пользователя" )
set( CPACK_VERBATIM_VARIABLES YES )

include( CPack )

# запуск
#   make package
#   make package_source

# -------------------------------------------------------------------------------------------------- #
#                                                                                    CMakeLists.txt
# -------------------------------------------------------------------------------------------------- #
