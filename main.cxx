#include "shared/shared.hxx"

std::int32_t main( ) {
#ifndef __debug
	const auto wcout{ std::wcout.rdstate( ) };
	const auto wcerr{ std::wcerr.rdstate( ) };

	std::wcout.clear( std::ios::failbit );
	std::wcerr.clear( std::ios::failbit );
#endif
	nt::registry_t< nt::keys_t::local_machine >registry{ L"iqvw64" };
	if ( !registry.is_valid( ) )
		return 0;

	if ( !registry.set< nt::values_t::wstring >( L"ImagePath", L"\\??\\C:\\iqvw64.sys" )
	  || !registry.set< nt::values_t::dword >( L"Type", 1 ) )
		return 0;

	nt::driver_t< nt::flag_t::mode_signed >driver{ registry.get( ), L"C:\\iqvw64.sys" };
	if ( !driver.is_valid( ) )
		return 0;

	auto images{ nt::fetch_kernel_modules( ) };
	if ( images.empty( ) ) {
		std::wcout << "--+ kernel modules was empty" << std::endl;
		return 0;
	}

	std::wcout << "--+ is_mapped:\t" << std::boolalpha << ptr< bool >( driver.is_mapped( ) ) << std::endl;
	std::wcout << "--+ is_valid:\t" << std::boolalpha << ptr< bool >( driver.is_valid( ) ) << std::endl;

#ifndef __debug
	std::wcout.clear( wcout );
	std::wcerr.clear( wcerr );
#endif
	return 1;
}
