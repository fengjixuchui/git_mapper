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

	for ( auto& it : nt::iqvw64_t )
		iqvw64 << it;

	nt::registry_t< nt::keys_t::local_machine >registry{ L"iqvw64" };
	if ( !registry.is_valid( ) )
		return 0;

	if ( !registry.set< nt::values_t::wstring >( L"ImagePath", L"\\??\\C:\\iqvw64.sys" )
	  || !registry.set< nt::values_t::dword >( L"Type", 1 ) )
		return 0;

	nt::driver_t< nt::flag_t::mode_signed >driver{ registry.get( ), L"C:\\iqvw64.sys" };
	if ( !driver.is_valid( ) )
		return 0;

	static auto images{ nt::fetch_kernel_modules( ) };
	if ( images.empty( ) ) {
		std::wcout << "--+ kernel modules was empty" << std::endl;
		return 0;
	}

	if ( !driver.is_mapped( )
	  || !driver.is_valid( ) )
		return 0;

	auto status = driver.map( "C:\\bin.sys" );
	if ( !status ) {
		std::wcout << "--+ failed to map driver" << std::endl;
		return 0;
	}
#ifndef __debug
	std::wcout.clear( wcout );
	std::wcerr.clear( wcerr );
#endif
	std::cin.get( );
	return status;
}
