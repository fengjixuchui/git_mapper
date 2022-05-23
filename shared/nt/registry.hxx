#pragma once

namespace nt {
	const enum keys_t : std::uint32_t {
		classes_root = 0x80000000,
		current_user = 0x80000001,
		local_machine = 0x80000002
	};

	const enum values_t : std::uint32_t {
		nullopt = 0x00000000,
		string = 0x00000001,
		wstring = 0x00000002,
		dword = 0x00000004,
		qword = 0x0000000c
	};

	template< keys_t type >
	struct registry_t {
	private:
		template< keys_t type >
		[[ nodiscard ]]
		const std::ptrdiff_t open_key(
			const std::wstring_view path
		) {
			if ( path.empty( ) ) {
				std::wcerr << "--+ key path was empty" << std::endl;
				return 0;
			}
			std::ptrdiff_t key{ };
		
			using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, const wchar_t*, std::ptrdiff_t* );
			if ( ptr< call_t >( &RegOpenKeyW )( type, path.data( ), &key ) ) {
				std::wcerr << "--+ failed to open key" << std::endl;
				return 0;
			}
			return key;
		}

		[[ nodiscard ]]
		const std::uint8_t close_key(
			const std::ptrdiff_t& key
		) {
			if ( !key ) {
				std::wcerr << "--+ key already closed" << std::endl;
				return 0;
			}

			using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t );
			if ( ptr< call_t >( &RegCloseKey )( key ) ) {
				std::wcerr << "--+ failed to close key" << std::endl;
				return 0;
			}
		
			*ptr< std::ptrdiff_t* >( &key ) = 0;
			return !key;
		}
	public:
		[[ nodiscard ]]
		const std::uint8_t is_valid(  ) {
			if ( m_entry.empty( ) )
				return 0;

			auto key{ open_key< type >( m_entry ) };
			if ( !key || key == -1 ) {
				m_entry.clear( );
				return 0;
			}

			if ( !close_key( key ) ) {
				m_entry.clear( );
				return 0;
			}
			return 1;
		}

		[[ nodiscard ]]
		const std::wstring get( ) {
			if ( !is_valid( ) ) {
				std::wcerr << "--+ invalid entry" << std::endl;
				m_entry.clear( );
				return L"";
			}
			return L"\\Registry\\Machine\\" + m_entry;
		}

		template< values_t value, typename type_t >
		const std::uint8_t set(
			const std::wstring_view name,
			const type_t buffer
		) {
			if ( name.empty( ) ) {
				std::wcerr << "--+ name was empty" << std::endl;
				return 0;
			}

			if ( !buffer ) {
				std::wcerr << "--+ invalid buffer" << std::endl;
				return 0;
			}

			if ( !is_valid( ) ) {
				std::wcerr << "--+ invalid entry" << std::endl;
				m_entry.clear( );
				return 0;
			}

			auto key{ open_key< type >( m_entry ) };
			if ( !key || key == -1 ) {
				std::wcerr << "--+ failed to open key" << std::endl;
				m_entry.clear( );
				return 0;
			}

			if ( value == values_t::string || value == values_t::wstring ) {
				using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, 
					std::ptrdiff_t, const wchar_t*, std::uint32_t, const type_t, std::int32_t );

				auto len{ std::wcslen( ptr< wchar_t* >( buffer ) ) * sizeof( wchar_t ) };
				if ( !len )
					std::wcerr << "--+ failed to get buffer length" << std::endl;

				if ( ptr< call_t >( &RegSetKeyValueW )( key, 0, name.data( ), value, buffer, len ) )
					std::wcerr << "--+ failed to set key value" << std::endl;
			}

			if ( value == values_t::dword || value == values_t::qword ) {
				using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, 
					std::ptrdiff_t, const wchar_t*, std::uint32_t, const type_t*, std::int32_t );

				if ( ptr< call_t >( &RegSetKeyValueW )( key, 0, name.data( ), value, &buffer, sizeof( type_t ) ) )
					std::wcerr << "--+ failed to set key value" << std::endl;
			}

			if ( !close_key( key ) ) {
				std::wcerr << "--+ failed to close key" << std::endl;
				m_entry.clear( );
				return 0;
			}
			return is_valid( );
		}
	private:
		template< keys_t type >
		[[ nodiscard ]]
		const std::ptrdiff_t create_key(
			const std::wstring_view path
		) {
			if ( path.empty( ) ) {
				std::wcerr << "--+ key path was empty" << std::endl;
				return 0;
			}
			std::ptrdiff_t key{ };

			using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, const wchar_t*, std::ptrdiff_t* );
			if ( ptr< call_t >( &RegCreateKeyW )( type, path.data( ), &key ) ) {
				std::wcerr << "--+ failed to create key" << std::endl;
				return 0;
			}
			return key;
		}

		template< keys_t type >
		[[ nodiscard ]]
		const std::ptrdiff_t clear_key(
			const std::wstring_view path
		) {
			if ( path.empty( ) ) {
				std::wcerr << "--+ key path was empty" << std::endl;
				return 0;
			}

			if ( !is_valid( ) ) {
				std::wcerr << "--+ key was invalid" << std::endl;
				return 0;
			}
		
			using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, const wchar_t* );
			if ( ptr< call_t >( &RegDeleteKeyW )( type, path.data( ) ) ) {
				std::wcerr << "--+ failed to clear key" << std::endl;
				return 0;
			}
			return 1;
		}
	public:
		[[ nodiscard ]]
		registry_t(
			const std::wstring_view name
		) {
			if ( name.empty( ) ) {
				std::wcerr << "--+ name was empty" << std::endl;
				return;
			}

			m_entry = L"SYSTEM\\CurrentControlSet\\Services\\" + std::wstring{ name };
			if ( m_entry.empty( ) ) {
				std::wcerr << "--+ m_entry was empty" << std::endl;
				return;
			}

			auto key{ create_key< type >( m_entry ) };
			if ( !key || key == -1 ) {
				std::wcerr << "--+ failed to create key" << std::endl;
				m_entry.clear( );
				return;
			}

			if ( !close_key( key ) ) {
				std::wcerr << "--+ failed to close key" << std::endl;
				m_entry.clear( );
				return;
			}
		}

		~registry_t( ) {
			if ( !is_valid( ) ) {
				std::wcerr << "--+ not clearing bad key" << std::endl;
				return;
			}

			if ( !clear_key< type >( m_entry ) ) {
				std::wcerr << "--+ failed to clear key" << std::endl;
				return;
			}
			m_entry.clear( );
		}
	private:
		std::wstring m_entry;
	};
}
