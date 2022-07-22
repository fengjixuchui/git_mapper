#pragma once

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <map>

#ifdef __ptr
   template< typename type_t = std::ptrdiff_t >
   type_t ptr( auto addr, std::int32_t fn = 0 ) {
      if ( fn )
         return ( *( type_t** )addr )[ fn ];
      return ( type_t )addr;
   };
#endif

#define __scope\
   for ( auto cond = 0; cond < 2; cond += 1 )\
      for ( ; cond < 2; cond += 2 )\
         if ( cond == 0 )\

#include "nt/utilities.hxx"
#include "nt/registry.hxx"
#include "nt/driver.hxx"
