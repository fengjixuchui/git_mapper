#include "shared/shared.hxx"

std::int32_t main(
	const std::int32_t arg_c,
	const char* arg_v[ ]
) {
#ifndef __debug
	const auto wcout{ std::wcout.rdstate( ) };
	const auto wcerr{ std::wcerr.rdstate( ) };

	std::wcout.clear( std::ios::failbit );
	std::wcerr.clear( std::ios::failbit );
#endif
	std::fstream iqvw64{ "C:\\iqvw64.sys", std::ios::binary | std::ios::out };
	if ( !iqvw64.is_open( ) ) {
		std::wcout << "--+ failed to create temporary file" << std::endl;
		return 0;
	}

	iqvw64.write( ptr< char* >( nt::iqvw64_t ), sizeof( nt::iqvw64_t ) );
	iqvw64.close( );

	__scope {
		nt::registry_t< nt::keys_t::local_machine >registry{ L"iqvw64" };
		if ( !registry.is_valid( ) ) {
			std::wcout << "--+ registry was invalid" << std::endl;
			break;
		}

		if ( !registry.set< nt::values_t::wstring >( L"ImagePath", L"\\??\\C:\\iqvw64.sys" )
		  || !registry.set< nt::values_t::dword >( L"Type", 1 ) )
			break;

		nt::driver_t< nt::flag_t::mode_signed >driver{ registry.get( ), L"C:\\iqvw64.sys" };
		if ( !driver.is_valid( ) ) {
			std::wcout << "--+ driver was invalid" << std::endl;
			break;
		}

		static auto images{ nt::fetch_kernel_modules( ) };
		if ( images.empty( ) ) {
			std::wcout << "--+ kernel modules was empty" << std::endl;
			break;
		}

		if ( !driver.is_mapped( )
		  || !driver.is_valid( ) )
			break;

		if ( !driver.map( "C:\\bin.sys" ) ) {
			std::wcout << "--+ failed to map driver" << std::endl;
			break;
		}

		std::wcout << "--+ successfully mapped driver" << std::endl;
	}
#ifndef __debug
	std::wcout.clear( wcout );
	std::wcerr.clear( wcerr );
#endif
	std::remove( "C:\\iqvw64.sys" );
	return 1;
}
