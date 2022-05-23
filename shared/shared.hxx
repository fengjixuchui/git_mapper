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

#include "nt/utilities.hxx"
#include "nt/registry.hxx"
#include "nt/driver.hxx"
