#pragma once

namespace nt {
	const enum flag_t : std::uint32_t {
		mode_signed = 0x00000000,
		mode_unsigned = 0x00000001
	};

	const enum file_t : std::uint32_t {
		any_access = 0x00000000,
		read_access = 0x80000000,
		write_access = 0x40000000,
		execute_access = 0x20000000
	};

	const enum mode_t : std::uint32_t {
		create_new = 0x00000001,
		create_always = 0x00000002,
		open_existing = 0x00000003,
		open_always = 0x00000004
	};

	const enum attr_t : std::uint32_t {
		readonly = 0x00000001,
		hidden = 0x00000002,
		system = 0x00000004,
		directory = 0x00000010,
		archive = 0x00000020,
		device = 0x00000040,
		normal = 0x00000080,
	};

	template< flag_t flag >
	struct driver_t {
	private:
		struct unicode_t {
			std::uint16_t m_length;
			std::uint16_t m_capacity;
			const wchar_t* m_buffer;
		};

		[[ nodiscard ]]
		const std::uint8_t adjust_privilege( ) {
			auto image{ GetModuleHandleW( L"ntdll.dll" ) };
			if ( !image ) {
				std::wcerr << "--+ failed to get ntdll.dll" << std::endl;
				return 0;
			}

			auto proc{ ptr< >( GetProcAddress( image, "RtlAdjustPrivilege" ) ) };
			if ( !proc ) {
				std::cerr << "--+ failed to get RtlAdjustPrivilege" << std::endl;
				return 0;
			}

			using call_t = std::int32_t( __stdcall* )( std::int32_t, 
				std::int32_t, std::int32_t, std::int32_t* );

			std::int32_t buf{ };
			if ( ptr< call_t >( proc )( 10, 1, 0, &buf ) ) {
				std::wcerr << "--+ failed to adjust privilege" << std::endl;
				return 0;
			}
			return 1;
		}

		[[ nodiscard ]]
		const std::uint8_t load_signed(
			const std::wstring_view registry
		) {
			if ( registry.empty( ) ) {
				std::wcerr << "--+ registry path was empty" << std::endl;
				return 0;
			}

			if ( !is_valid( ) ) {
				std::wcerr << "--+ invalid path or registry" << std::endl;
				return 0;
			}

			if ( is_mapped( ) ) {
				std::wcerr << "--+ driver was already mapped" << std::endl;
				return 0;
			}

			if ( !adjust_privilege( ) ) {
				std::wcerr << "--+ failed to adjust privilege" << std::endl;
				return 0;
			}

			auto image{ GetModuleHandleW( L"ntdll.dll" ) };
			if ( !image ) {
				std::wcerr << "--+ failed to get ntdll.dll" << std::endl;
				return 0;
			}

			auto proc{ ptr< >( GetProcAddress( image, "NtLoadDriver" ) ) };
			if ( !proc ) {
				std::cerr << "--+ failed to get NtLoadDriver" << std::endl;
				return 0;
			}

			unicode_t stub{
				.m_length = static_cast< std::uint16_t >( registry.length( ) * sizeof( wchar_t ) ),
				.m_capacity = static_cast< std::uint16_t >( stub.m_length + 2 ),
				.m_buffer = registry.data( )
			};

			using call_t = std::int32_t( __stdcall* )( unicode_t* );
			auto ctx{ ptr< call_t >( proc )( &stub ) };
			if ( ctx ) {
				std::wcerr << "--+ failed to map signed driver 0x" << std::hex << ctx << std::endl;
				return 0;
			}
			
			if ( !is_mapped( ) ) {
				std::wcerr << "--+ cannot open device to mapped driver" << std::endl;
				return 0;
			}
			return 1;
		}

		[[ nodiscard ]]
		const std::uint8_t unload_signed(
			const std::wstring_view registry
		) {
			if ( registry.empty( ) ) {
				std::wcerr << "--+ registry path was empty" << std::endl;
				return 0;
			}

			if ( !is_valid( ) ) {
				std::wcerr << "--+ invalid path or registry" << std::endl;
				return 0;
			}

			if ( !is_mapped( ) ) {
				std::wcerr << "--+ driver was not mapped" << std::endl;
				return 0;
			}

			if ( !adjust_privilege( ) ) {
				std::wcerr << "--+ failed to adjust privilege" << std::endl;
				return 0;
			}

			auto image{ GetModuleHandleW( L"ntdll.dll" ) };
			if ( !image ) {
				std::wcerr << "--+ failed to get ntdll.dll" << std::endl;
				return 0;
			}

			auto proc{ ptr< >( GetProcAddress( image, "NtUnloadDriver" ) ) };
			if ( !proc ) {
				std::cerr << "--+ failed to get NtUnloadDriver" << std::endl;
				return 0;
			}

			unicode_t stub{
				.m_length = static_cast< std::uint16_t >( registry.length( ) * sizeof( wchar_t ) ),
				.m_capacity = static_cast< std::uint16_t >( stub.m_length + 2 ),
				.m_buffer = registry.data( )
			};

			using call_t = std::int32_t( __stdcall* )( unicode_t* );
			auto ctx{ ptr< call_t >( proc )( &stub ) };
			if ( ctx ) {
				std::wcerr << "--+ failed to unmap signed driver 0x" << std::hex << ctx << std::endl;
				return 0;
			}
			
			if ( is_mapped( ) ) {
				std::wcerr << "--+ can still open device to unmapped driver" << std::endl;
				return 0;
			}
			return 1;
		}


		[[ nodiscard ]]
		const std::uint8_t close_device(
			const std::ptrdiff_t& device
		) {
			if ( !device )
				return 0;

			using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t );
			if ( !ptr< call_t >( &CloseHandle )( device ) ) {
				*ptr< std::ptrdiff_t* >( &device ) = 0;
				return 0;
			}
			
			*ptr< std::ptrdiff_t* >( &device ) = 0;
			return 1;
		}

		[[ nodiscard ]]
		const std::ptrdiff_t open_device(
			const std::int32_t access,
			const std::int32_t mode,
			const std::int32_t attribute
		) {
			if ( !mode || !attribute )
				return 0;

			using call_t = std::ptrdiff_t( __stdcall* )( const wchar_t*, std::int32_t, 
				std::int32_t, std::ptrdiff_t, std::int32_t, std::int32_t, std::ptrdiff_t );

			return ptr< call_t >( &CreateFileW )( L"\\\\.\\Nal", access, 0, 0, mode, attribute, 0 );
		}

		[[ nodiscard ]]
		const std::ptrdiff_t get( ) {
			if ( !is_valid( ) || !is_mapped( ) ) {
				std::wcerr << "--+ invalid entry or driver not mapped" << std::endl;
				return 0;
			}

			auto ctx{ open_device( file_t::read_access | file_t::write_access, 
				mode_t::open_existing, attr_t::normal ) };
			if ( !ctx || ctx == -1 ) {
				std::wcerr << "--+ failed to open device" << std::endl;
				return 0;
			}
			return ctx;
		}
	public:
		template< typename type_t >
		[[ nodiscard ]]
		const type_t read(
			const auto src,
			const std::size_t size = sizeof( type_t )
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access, 
				mode_t::open_existing, attr_t::normal ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct copy_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_src, m_dst;
				std::size_t m_size;
			};

			type_t out{ };

			copy_mem_t call{ 
				.m_index = 0x33, 
				.m_src = ptr< std::ptrdiff_t >( src ), 
				.m_dst = ptr< std::ptrdiff_t >( &out ),
				.m_size = size
			};

			if ( !io_ctl< copy_mem_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return out;
		}

		template< typename type_t >
		const std::uint8_t write(
			const auto dst,
			const type_t src,
			const std::size_t size = sizeof( type_t )
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access, 
				mode_t::open_existing, attr_t::normal ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct copy_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_src, m_dst;
				std::size_t m_size;
			};

			copy_mem_t call{ 
				.m_index = 0x33, 
				.m_src = ptr< std::ptrdiff_t >( &src ), 
				.m_dst = ptr< std::ptrdiff_t >( dst ),
				.m_size = size
			};

			if ( !io_ctl< copy_mem_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return 1;
		}

		[[ nodiscard ]]
		const std::uint8_t is_mapped( ) {
			if ( m_registry.empty( ) || m_path.empty( ) )
				return 0;

			auto ctx{ open_device( file_t::any_access, 
				mode_t::open_existing, attr_t::normal ) };
			if ( !ctx || ctx == -1 )
				return 0;
			return close_device( ctx );
		}

		[[ nodiscard ]]
		const std::uint8_t is_valid( ) {
			if ( m_registry.empty( ) || m_path.empty( ) )
				return 0;

			if ( !std::filesystem::exists( m_path ) )
				return 0;

			auto ext{ std::filesystem::path{ m_path }.extension( ) };
			if ( ext.empty( ) || ext != ".sys" )
				return 0;

			std::ifstream file{ m_path, std::ios::in | std::ios::binary };
			if ( !file.is_open( ) || !file.good( ) )
				return 0;

			std::uint16_t magic{ };
			if ( !file.read( ptr< char* >( &magic ), 0x2 ) )
				return 0;

			return !!( magic == 'ZM' );
		}

		const std::uint8_t map( ) {
			if ( !is_mapped( ) || !is_valid( ) ) {
				std::wcerr << "--+ driver was not mapped or bad registry" << std::endl;
				return 0;
			}
			std::wcout << "--+ mapping..." << std::endl;
			return 1;
		}

		[[ nodiscard ]]
		driver_t(
			const std::wstring registry,
			const std::wstring_view path
		) {
			if ( registry.empty( ) || path.empty( ) ) {
				std::wcerr << "--+ path or registry was empty" << std::endl;
				return;
			}

			m_registry = registry, m_path = path;
			if ( !is_valid( ) ) {
				std::wcerr << "--+ invalid registry or path" << std::endl;
				return;
			}

			if ( is_mapped( ) ) {
				if ( !unload_signed( m_registry ) ) {
					std::wcerr << "--+ failed to unload driver" << std::endl;
				}
			}

			if ( !load_signed( m_registry ) ) {
				std::wcerr << "--+ failed to map signed driver" << std::endl;
			}
		}

		~driver_t( ) {
			if ( is_mapped( ) && !m_registry.empty( ) ) {
				if ( !unload_signed( m_registry ) )
					std::wcerr << "--+ failed to unload mapped driver" << std::endl;
			} else {
				std::wcerr << "--+ unmapped driver or bad registry" << std::endl;
				return;
			}
			if ( !is_valid( ) )
				std::wcerr << "--+ invalid path or registry" << std::endl;
			m_path.clear( ), m_registry.clear( );
		}
	private:
		std::wstring m_path, m_registry;
	};
}
