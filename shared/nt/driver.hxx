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
			const std::int32_t mode = mode_t::open_existing,
			const std::int32_t attribute = attr_t::normal
		) {
			if ( !mode || !attribute )
				return 0;

			using call_t = std::ptrdiff_t( __stdcall* )( const wchar_t*, std::int32_t, 
				std::int32_t, std::ptrdiff_t, std::int32_t, std::int32_t, std::ptrdiff_t );

			return ptr< call_t >( &CreateFileW )( L"\\\\.\\Nal", access, 0, 0, mode, attribute, 0 );
		}

		const std::ptrdiff_t map_io(
			const std::ptrdiff_t src,
			const std::uint32_t size
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct map_io_t {
				std::uint64_t m_index, m_unused, m_reserved;
				std::ptrdiff_t m_dst, m_src;
				std::uint32_t m_size;
			};

			map_io_t call{
				.m_index = 0x19, 
				.m_src = ptr< >( src ),
				.m_size = size
			};

			if ( !io_ctl< map_io_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return call.m_dst;
		}

		const std::uint8_t unmap_io(
			const std::ptrdiff_t src,
			const std::uint32_t size
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct map_io_t {
				std::uint64_t m_index, m_unused, m_reserved;
				std::ptrdiff_t m_src, m_dst;
				std::uint32_t m_size;
			};

			map_io_t call{
				.m_index = 0x1a, 
				.m_src = ptr< >( src ),
				.m_size = size
			};

			if ( !io_ctl< map_io_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return 1;
		}

		const std::ptrdiff_t fetch_physical(
			const std::ptrdiff_t src
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct phys_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_dst, m_src;
			};

			phys_mem_t call{
				.m_index = 0x25, 
				.m_src = ptr< >( src )
			};

			if ( !io_ctl< phys_mem_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return call.m_dst;
		}

public:
		template< typename type_t >
		[[ nodiscard ]]
		const type_t read(
			const auto src,
			const std::size_t size = sizeof( type_t )
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return type_t{ };

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return type_t{ };

			struct copy_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_src, m_dst;
				std::size_t m_size;
			};

			type_t buffer{ };

			copy_mem_t call{ 
				.m_index = 0x33, 
				.m_src = ptr< >( src ), 
				.m_dst = ptr< >( &buffer ),
				.m_size = size
			};

			if ( !io_ctl< copy_mem_t >( ctx, &call ) || !close_device( ctx ) )
				return type_t{ };

			return buffer;
		}

		template< typename type_t >
		const std::uint8_t write(
			const auto dst,
			const type_t src,
			const std::size_t size = sizeof( type_t )
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return 0;

			struct copy_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_src, m_dst;
				std::size_t m_size;
			};

			copy_mem_t call{
				.m_index = 0x33, 
				.m_src = ptr< >( &src ), 
				.m_dst = ptr< >( dst ),
				.m_size = size
			};

			if ( !io_ctl< copy_mem_t >( ctx, &call ) || !close_device( ctx ) )
				return 0;

			return 1;
		}

		template< typename type_t, typename... arg_t >
		type_t call(
			const std::ptrdiff_t address,
			arg_t... args
		) {
			auto ntdll{ GetModuleHandleW( L"ntdll.dll" ) };
			if ( !ntdll ) {
				std::wcout << "--+ failed to get ntdll.dll" << std::endl;
				return type_t{ };
			}

			auto addr{ ptr< >( GetProcAddress( ntdll, "NtAddAtom" ) ) };
			if ( !addr ) {
				std::wcout << "--+ failed to get NtAddAtom" << std::endl;
				return type_t{ };
			}

			std::uint8_t jmp[ 12 ] = { 0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xe0 };
			std::uint8_t old[ 12 ] = { 0x48, 0x83, 0xec, 0x28, 0x45, 0x33, 0xc9, 0xe8, 0x14, 0x5a, 0xd6, 0xff };

			*ptr< std::ptrdiff_t* >( &jmp[ 2 ] ) = address;
			if ( !address ) {
				std::wcout << "--+ bad function address" << std::endl;
				return type_t{ };
			}

			auto images{ fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ failed to get modules" << std::endl;
				return type_t{ };
			}

			auto kernel{ fetch_export( images[ L"ntoskrnl.exe" ], L"NtAddAtom" ) };
			if ( !kernel ) {
				std::wcout << "--+ failed to get kernel NtAddAtom" << std::endl;
				return type_t{ };
			}

			auto ctx{ map_io( fetch_physical( kernel ), 12 ) };
			if ( !ctx ) {
				std::wcout << "--+ failed to map_io kernel address" << std::endl;
				return type_t{ };
			}

			for ( std::size_t i{ }; i < 12; i++ )
				write< std::uint8_t >( ctx + i, jmp[ i ] );
			
			auto ret{ ptr< type_t( __stdcall* )( arg_t... ) >( addr )( args... ) };
			
			for ( std::size_t i{ }; i < 12; i++ )
				write< std::uint8_t >( ctx + i, old[ i ] );

			if ( !unmap_io( ctx, 12 ) ) {
				std::wcout << "--+ failed to unmap_io kernel address" << std::endl;
				return type_t{ };
			}

			return ret;
		}

		[[ nodiscard ]]
		const std::ptrdiff_t fetch_export(
			const std::pair< std::ptrdiff_t, std::size_t >module,
			const std::wstring_view function
		) {
			if ( !is_valid( ) || !is_mapped( ) )
				return 0;

			auto images{ fetch_kernel_modules( ) };
			if ( images.empty( ) )
				return 0;

			struct dos_header_t {
				std::uint16_t m_magic;
				std::int8_t m_pad0[58];
				std::uint32_t m_next;
			};

			struct nt_headers_t {
				std::uint16_t m_magic;
				std::int8_t m_pad0[132];
				std::int32_t m_address, m_size;
				std::int8_t m_pad1[120];
			};

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return{ };

			dos_header_t dos_header{ read< dos_header_t >( std::get< 0 >( module ) ) };
			nt_headers_t nt_headers{ read< nt_headers_t >( std::get< 0 >( module ) + dos_header.m_next ) };

			if ( dos_header.m_magic != 'ZM' || nt_headers.m_magic != 'EP' )
				return 0;

			struct export_dir_t {
				std::int8_t m_pad0[24];
				std::int32_t m_count, m_fn_ptr;
				std::int32_t m_tag_ptr, m_ord_ptr;
			};

			auto dir{ mem_alloc< export_dir_t* >( 0, nt_headers.m_size ) };
			if ( !dir )
				return 0;

			struct copy_mem_t {
				std::uint64_t m_index, m_unused;
				std::ptrdiff_t m_src, m_dst;
				std::size_t m_size;
			};

			copy_mem_t call{ 
				.m_index = 0x33, 
				.m_src = ptr< >( std::get< 0 >( module ) + nt_headers.m_address ), 
				.m_dst = ptr< >( dir ),
				.m_size = ptr< std::size_t >( nt_headers.m_size )
			};

			if ( !io_ctl< copy_mem_t >( ctx, &call ) || !close_device( ctx ) ) {
				mem_free( dir, nt_headers.m_size );
				return 0;
			}

			auto rva{ ptr< >( dir ) - nt_headers.m_address };
			if ( !rva ) {
				mem_free( dir, nt_headers.m_size );
				return 0;
			}

			auto fn_tag{ ptr< std::uint32_t* >( dir->m_tag_ptr + rva ) };
			auto fn_ord{ ptr< std::uint16_t* >( dir->m_ord_ptr + rva ) };
			auto fn_ptr{ ptr< std::uint32_t* >( dir->m_fn_ptr + rva ) };

			if ( !fn_tag || !fn_ord || !fn_ptr ) {
				mem_free( dir, nt_headers.m_size );
				return 0;
			}

			for ( std::size_t i{ }; i < dir->m_count; i++ ) {
				std::string name{ ptr< char* >( fn_tag[i] + rva ) };
				if ( name.empty( ) )
					continue;

				if ( function == std::wstring{ name.begin( ), name.end( ) } ) {
					mem_free( dir, nt_headers.m_size );
					return ptr< >( std::get< 0 >( module ) + fn_ptr[fn_ord[i]] );
				}
			}

			mem_free( dir, nt_headers.m_size );
			return 0;
		}

		[[ nodiscard ]]
		const std::uint8_t is_mapped( ) {
			if ( m_registry.empty( ) || m_path.empty( ) )
				return 0;

			auto ctx{ open_device( file_t::any_access ) };
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
			if ( flag != flag_t::mode_signed ) {
				std::wcerr << "--+ expected signed mode" << std::endl;
				return;
			}

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
				return;
			}
		}

		~driver_t( ) {
			if ( !is_mapped( ) ) {
				std::wcerr << "--+ not unloading unmapped driver" << std::endl;
				return;
			}

			auto images{ fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcerr << "--+ improper unload" << std::endl;
				return;
			}

			if ( !unload_signed( m_registry ) ) {
				std::wcerr << "--+ failed to unload mapped driver" << std::endl;
				return;
			}
		}
	private:
		std::wstring m_path, m_registry;
	};
}
