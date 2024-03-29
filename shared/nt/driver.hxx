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

	const enum pte_t : std::uint16_t {
		valid = 0x00000001,
		access = 0x00000020,
		dirty = 0x00000042,
		global = 0x00000100,
		writable = 0x00000800
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

		const std::ptrdiff_t get_kernel_cr3( ) {
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto system{ fetch_export( images[ L"ntoskrnl.exe" ], L"PsInitialSystemProcess" ) };
			if ( !system ) {
				std::wcout << "--+ failed to resolve PsInitialSystemProcess" << std::endl;
				return 0;
			}

			auto dir_base{ read< std::ptrdiff_t >( system + 0x28 ) };
         auto usr_base{ read< std::ptrdiff_t >( system + 0x280 ) };

         return dir_base ? dir_base : usr_base;
		}

		const std::uint8_t is_discarded(
			const std::ptrdiff_t addr
		) {
			enum id_t : std::uint8_t {
            pte_base,
				pde_base,
				ppe_base,
				pxe_base
         };
			
			const std::ptrdiff_t page[ ] = {
				fetch_pte_base( ),
				page[ pte_base ] + ( ( page[ pte_base ] & 0xffffffffffff ) >> 9 ),
				page[ pte_base ] + ( ( page[ pde_base ] & 0xffffffffffff ) >> 9 ),
				page[ pte_base ] + ( ( page[ ppe_base ] & 0xffffffffffff ) >> 9 )
			};

			auto pte_ptr{ ( ( ( addr & 0xffffffffffff ) >> 12 ) << 3 ) + page[ pte_base ] };
			auto pde_ptr{ ( ( ( addr & 0xffffffffffff ) >> 21 ) << 3 ) + page[ pde_base ] };
			auto ppe_ptr{ ( ( ( addr & 0xffffffffffff ) >> 30 ) << 3 ) + page[ ppe_base ] };
			auto pxe_ptr{ ( ( ( addr & 0xffffffffffff ) >> 39 ) << 3 ) + page[ pxe_base ] };

			if ( !( read< std::ptrdiff_t >( pde_ptr ) & 0x1ll )
			  || !( read< std::ptrdiff_t >( ppe_ptr ) & 0x1ll ) 
			  || !( read< std::ptrdiff_t >( pxe_ptr ) & 0x1ll ) )
				return 0;

			return read< std::ptrdiff_t >( pte_ptr ) == 0;
		}

		const std::ptrdiff_t fetch_pfn_database( ) {
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto thread_state{ fetch_export( images[ L"ntoskrnl.exe" ], L"KeCapturePersistentThreadState" ) };
			if ( !thread_state ) {
				std::wcout << "--+ failed to get KeCapturePersistentThreadState" << std::endl;
				return 0;
			}

			//
			// b9 ff ff 00 00				mov ecx, 0ffffh
			// 48 8b 05 80 c1 2d 00		mov rax, cs:MmPfnDatabase
			// 48 89 43 18					mov [ rbx + 18h ], rax
			//

			while ( read< std::uint8_t >( thread_state - 5 ) != 0x00
				  || read< std::uint8_t >( thread_state - 4 ) != 0x00
				  || read< std::uint8_t >( thread_state - 3 ) != 0x48
				  || read< std::uint8_t >( thread_state - 2 ) != 0x8b
				  || read< std::uint8_t >( thread_state - 1 ) != 0x05 )
				thread_state++;

			static auto pfn_database_ptr{ read< std::int32_t >( thread_state ) + thread_state + 4 };
			if ( !pfn_database_ptr ) {
				std::wcout << "--+ failed to resolve pfn database pointer" << std::endl;
				return 0;
			}

			static auto pfn_database{ read< std::ptrdiff_t >( pfn_database_ptr ) };
			if ( !pfn_database ) {
				std::wcout << "--+ failed to read pfn database pointer" << std::endl;
				return 0;
			}

			return pfn_database;
		}

		const std::ptrdiff_t fetch_pte_base( ) {
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto bug_check_ex{ fetch_export( images[ L"ntoskrnl.exe" ], L"KeBugCheckEx" ) };
			if ( !bug_check_ex ) {
				std::wcout << "--+ failed to get KeBugCheckEx" << std::endl;
				return 0;
			}

			//
			// 45 33 c0				xor r8d, r8d
			// 33 d2					xor edx, edx
			// e8 82 6e 0e 00		call KeBugCheck2
			//

			while ( read< std::uint8_t >( bug_check_ex - 5 ) != 0x33
				  || read< std::uint8_t >( bug_check_ex - 4 ) != 0xc0
				  || read< std::uint8_t >( bug_check_ex - 3 ) != 0x33
				  || read< std::uint8_t >( bug_check_ex - 2 ) != 0xd2
				  || read< std::uint8_t >( bug_check_ex - 1 ) != 0xe8 )
				bug_check_ex++;

			static auto bug_check{ read< std::int32_t >( bug_check_ex ) + bug_check_ex + 4 };
			if ( !bug_check ) {
				std::wcout << "--+ failed to resolve KeBugCheck2" << std::endl;
				return 0;
			}

			//
			// 48 8b 15 53 65 1a 00		mov rdx, cs:qword_fffff8041364f270
			// 48 8b 0d 44 65 1a 00		mov rcx, cs:qword_fffff8041364f268
			// e8 f3 f8 ef ff				call KiMarkBugCheckRegions
			//

			while ( read< std::uint8_t >( bug_check - 8 ) != 0x48
				  || read< std::uint8_t >( bug_check - 7 ) != 0x8b
				  || read< std::uint8_t >( bug_check - 6 ) != 0x0d
				  || read< std::uint8_t >( bug_check - 1 ) != 0xe8 )
				bug_check++;

			static auto mark_regions{ read< std::int32_t >( bug_check ) + bug_check + 4 };
			if ( !mark_regions ) {
				std::wcout << "--+ failed to resolve KiMarkBugCheckRegions" << std::endl;
				return 0;
			}

			//
			// 84 c0							test al, al
			// 0f 84 98 00 00 00			jz loc_fffff804133a8774
			// 48 8b 05 a5 ac 3c 00		mov rax, cs:MmPteBase
			//

			while ( read< std::uint8_t >( mark_regions - 9 ) != 0x0f
				  || read< std::uint8_t >( mark_regions - 8 ) != 0x84
				  || read< std::uint8_t >( mark_regions - 3 ) != 0x48
				  || read< std::uint8_t >( mark_regions - 2 ) != 0x8b
				  || read< std::uint8_t >( mark_regions - 1 ) != 0x05 )
				mark_regions++;

			static auto pte_base_ptr{ read< std::uint32_t >( mark_regions ) + mark_regions + 4 };
			if ( !pte_base_ptr ) {
				std::wcout << "--+ failed to resolve pte base pointer" << std::endl;
				return 0;
			}

			static auto pte_base{ read< std::ptrdiff_t >( pte_base_ptr ) };
			if ( !pte_base ) {
				std::wcout << "--+ failed to read pte base" << std::endl;
				return 0;
			}

			return pte_base;
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

			static auto images{ fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ failed to get modules" << std::endl;
				return type_t{ };
			}

			static auto kernel{ fetch_export( images[ L"ntoskrnl.exe" ], L"NtAddAtom" ) };
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

			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) )
				return 0;

			struct dos_header_t {
				std::uint16_t m_magic;
				std::int8_t m_pad0[ 58 ];
				std::uint32_t m_next;
			};

			struct nt_headers_t {
				std::uint16_t m_magic;
				std::int8_t m_pad0[ 132 ];
				std::int32_t m_address, m_size;
				std::int8_t m_pad1[ 120 ];
			};

			auto ctx{ open_device( file_t::read_access | file_t::write_access ) };
			if ( !ctx || ctx == -1 )
				return 0;

			dos_header_t dos_header{ read< dos_header_t >( module.first ) };
			nt_headers_t nt_headers{ read< nt_headers_t >( module.first + dos_header.m_next ) };

			if ( dos_header.m_magic != 'ZM' || nt_headers.m_magic != 'EP' )
				return 0;

			struct export_dir_t {
				std::int8_t m_pad0[ 24 ];
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
				.m_src = ptr< >( module.first + nt_headers.m_address ), 
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
				std::string name{ ptr< char* >( fn_tag[ i ] + rva ) };
				if ( name.empty( ) )
					continue;

				if ( function == std::wstring{ name.begin( ), name.end( ) } ) {
					mem_free( dir, nt_headers.m_size );
					return ptr< >( module.first + fn_ptr[ fn_ord[ i ] ] );
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

		[[ nodiscard ]]
		const std::pair< std::ptrdiff_t, std::size_t >fetch_max_discard( ) {
			static auto images{ fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ failed to get modules" << std::endl;
				return { };
			}

			std::map< std::wstring, std::vector< std::ptrdiff_t > >sections{ };

			for ( auto& [ key, val ] : images ) {
				if ( key.find( L".dll" ) != std::wstring::npos )
					continue;

				if ( val.first <= images[ L"ntoskrnl.exe" ].first )
					continue;

				for ( auto ctx{ val.first }; ctx < val.first + val.second; ctx += 0x1000 )
					if ( is_discarded( ctx ) )
						sections[ key ].push_back( ctx );
			}

			std::pair< std::ptrdiff_t, std::size_t >max_discard{ };

			for ( auto& [ key, val ] : sections )
				if ( val.size( ) > max_discard.second )
					max_discard = std::make_pair( val.front( ), val.size( ) );

			return std::make_pair( max_discard.first, max_discard.second * 0x1000 );
		};

		const std::ptrdiff_t fetch_get_page_addr( ) { 
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto alloc_profiles{ fetch_export( images[ L"ntoskrnl.exe" ], L"KeAllocateProcessorProfileStructures" ) };
			if ( !alloc_profiles ) {
				std::wcout << "--+ failed to resolve KeAllocateProcessorProfileStructures" << std::endl;
				return 0;
			}

			//
			// 33 d2					xor edx, edx
			// 49 8b ce				mov rcx, r14
			// e8 f1 a8 f7 ff		call MmAllocateIndependentPagesEx
			//

			while ( read< std::uint8_t >( alloc_profiles - 5 ) != 0xd2
				  || read< std::uint8_t >( alloc_profiles - 4 ) != 0x49
				  || read< std::uint8_t >( alloc_profiles - 3 ) != 0x8b
				  || read< std::uint8_t >( alloc_profiles - 2 ) != 0xce
				  || read< std::uint8_t >( alloc_profiles - 1 ) != 0xe8 )
				alloc_profiles++;

			static auto alloc_pages{ read< std::int32_t >( alloc_profiles ) + alloc_profiles + 4 };
			if ( !alloc_pages ) {
				std::wcout << "--+ failed to resolve MmAllocateIndependentPagesEx" << std::endl;
				return 0;
			}

			//
			// 48 8d 0d 99 bd 36 00		lea rcx, MiSystemPartition ; Load Effective Address
			// 41 8b d7						mov edx, r15d
			// e8 31 9b f7 ff				call MiGetPage
			//

			while ( read< std::uint8_t >( alloc_pages - 9 ) != 0x0d
				  || read< std::uint8_t >( alloc_pages - 4 ) != 0x41
				  || read< std::uint8_t >( alloc_pages - 3 ) != 0x8b
				  || read< std::uint8_t >( alloc_pages - 2 ) != 0xd7
				  || read< std::uint8_t >( alloc_pages - 1 ) != 0xe8 )
				alloc_pages++;

			static auto get_page_addr{ read< std::int32_t >( alloc_pages ) + alloc_pages + 4 };
			if ( !get_page_addr ) {
				std::wcout << "--+ failed to resolve MiGetPage" << std::endl;
				return 0;
			}

			return get_page_addr;
		}
		const std::ptrdiff_t fetch_init_pfn_addr( ) { 
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto alloc_profiles{ fetch_export( images[ L"ntoskrnl.exe" ], L"KeAllocateProcessorProfileStructures" ) };
			if ( !alloc_profiles ) {
				std::wcout << "--+ failed to resolve KeAllocateProcessorProfileStructures" << std::endl;
				return 0;
			}

			//
			// 33 d2					xor edx, edx
			// 49 8b ce				mov rcx, r14
			// e8 f1 a8 f7 ff		call MmAllocateIndependentPagesEx
			//

			while ( read< std::uint8_t >( alloc_profiles - 5 ) != 0xd2
				  || read< std::uint8_t >( alloc_profiles - 4 ) != 0x49
				  || read< std::uint8_t >( alloc_profiles - 3 ) != 0x8b
				  || read< std::uint8_t >( alloc_profiles - 2 ) != 0xce
				  || read< std::uint8_t >( alloc_profiles - 1 ) != 0xe8 )
				alloc_profiles++;

			static auto alloc_pages{ read< std::int32_t >( alloc_profiles ) + alloc_profiles + 4 };
			if ( !alloc_pages ) {
				std::wcout << "--+ failed to resolve MmAllocateIndependentPagesEx" << std::endl;
				return 0;
			}

			//
			//	44 8b c8				mov r9d, eax
			//	44 8b c0				mov r8d, eax
			//	e8 fc 02 00 00		call MiInitializePfn
			//

			while ( read< std::uint8_t >( alloc_pages - 5 ) != 0xc8
				  || read< std::uint8_t >( alloc_pages - 4 ) != 0x44
				  || read< std::uint8_t >( alloc_pages - 3 ) != 0x8b
				  || read< std::uint8_t >( alloc_pages - 2 ) != 0xc0
				  || read< std::uint8_t >( alloc_pages - 1 ) != 0xe8 )
				alloc_pages++;

			static auto init_pfn_addr{ read< std::int32_t >( alloc_pages ) + alloc_pages + 4 };
			if ( !init_pfn_addr ) {
				std::wcout << "--+ failed to resolve MiInitializePfn" << std::endl;
				return 0;
			}

			return init_pfn_addr;
		}

		const std::ptrdiff_t fetch_system_partition( ) {
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto add_physical{ fetch_export( images[ L"ntoskrnl.exe" ], L"MmAddPhysicalMemory" ) };
			if ( !add_physical ) {
				std::wcout << "--+ failed to resolve MmAddPhysicalMemory" << std::endl;
				return 0;
			}

			while ( read< std::uint8_t >( add_physical - 5 ) != 0xb6
				  || read< std::uint8_t >( add_physical - 4 ) != 0xc8
				  || read< std::uint8_t >( add_physical - 3 ) != 0x48
				  || read< std::uint8_t >( add_physical - 2 ) != 0x8d
				  || read< std::uint8_t >( add_physical - 1 ) != 0x0d )
				add_physical++;

			static auto system_partition{ read< std::int32_t >( add_physical ) + add_physical + 4 };
			if ( !system_partition ) {
				std::wcout << "--+ failed to resolve MiSystemPartition" << std::endl;
				return 0;
			}

			return system_partition;
		}

		[[ nodiscard ]]
		const std::ptrdiff_t get_relocate_addr( ) {
			static auto images{ nt::fetch_kernel_modules( ) };
			if ( images.empty( ) ) {
				std::wcout << "--+ kernel modules was empty" << std::endl;
				return 0;
			}

			static auto load_image{ fetch_export( images[ L"ntoskrnl.exe" ], L"MmLoadSystemImage" ) };
			if ( !load_image ) {
				std::wcout << "--+ failed to resolve MmLoadSystemImage" << std::endl;
				return 0;
			}

			//
			// 8b d6					mov edx, esi
			// 48 8b 4c 24 70		mov rcx, [ rsp + 1A0h + var_130 ]
			// e8 b1 39 0b 00		call MiMapSystemImageWithLargePage
			//

			while ( read< std::uint8_t >( load_image - 5 ) != 0x8b
				  || read< std::uint8_t >( load_image - 4 ) != 0x4c
				  || read< std::uint8_t >( load_image - 3 ) != 0x24
				  || read< std::uint8_t >( load_image - 2 ) != 0x70
				  || read< std::uint8_t >( load_image - 1 ) != 0xe8 )
				load_image++;

			static auto map_image{ read< std::int32_t >( load_image ) + load_image + 4 };
			if ( !map_image ) {
				std::wcout << "--+ failed to resolve MiMapSystemImageWithLargePage" << std::endl;
				return 0;
			}

			//
			// 77 cd					ja short loc_fffff80434c9ba77
			// 48 8b cb				mov rcx, rbx
			// e8 52 de 03 00		call LdrRelocateImageWithBias
			//

			while ( read< std::uint8_t >( map_image - 5 ) != 0xcd
				  || read< std::uint8_t >( map_image - 4 ) != 0x48
				  || read< std::uint8_t >( map_image - 3 ) != 0x8b
				  || read< std::uint8_t >( map_image - 2 ) != 0xcb
				  || read< std::uint8_t >( map_image - 1 ) != 0xe8 )
				map_image++;

			static auto relocate_addr{ read< std::int32_t >( map_image ) + map_image + 4 };
			if ( !relocate_addr ) {
				std::wcout << "--+ failed to resolve LdrRelocateImageWithBias" << std::endl;
				return 0;
			}

			return relocate_addr;
		}

		[[ nodiscard ]]
		const std::uint8_t map(
			const std::filesystem::path path
		) {
			if ( !std::filesystem::exists( path ) ) {
				std::wcout << "--+ file does not exist at path" << std::endl;
				return 0;
			}

			auto ext{ std::filesystem::path{ path }.extension( ) };
			if ( ext.empty( ) || ext != ".sys" ) {
				std::wcout << "--+ file has invalid extension" << std::endl;
				return 0;
			}

			std::ifstream file{ path, std::ios::in | std::ios::binary };
			if ( !file.is_open( ) || !file.good( ) ) {
				std::wcout << "--+ failed to open file stream" << std::endl;
				return 0;
			}

			static std::vector< std::uint8_t >driver_bytes{
				std::istreambuf_iterator< char >( file ),
				std::istreambuf_iterator< char >( )
			};

			struct dos_header_t {
				std::uint16_t m_magic;
				std::int8_t m_pad0[ 58 ];
				std::uint32_t m_next;
			};

			struct nt_headers_t {
				std::uint16_t m_magic;
				std::int8_t m_pad1[ 38 ];
				std::uint32_t m_entry;
				std::int8_t m_pad2[ 220 ];
			};

			auto dos_header{ ptr< dos_header_t* >( &driver_bytes.front( ) ) };
			auto nt_headers{ ptr< nt_headers_t* >( &driver_bytes.front( ) + dos_header->m_next ) };

			if ( dos_header->m_magic != 'ZM' || nt_headers->m_magic != 'EP' ) {
				std::wcout << "--+ bad dos and nt header magic" << std::endl;
				return 0;
			}

			auto max_discard{ fetch_max_discard( ) };
			if ( !max_discard.first || max_discard.second < driver_bytes.size( ) ) {
				std::wcout << "--+ unable to find large enough discard list" << std::endl;
				return 0;
			}

			auto pte_addr{ ( ( ( max_discard.first & 0xffffffffffff ) >> 12 ) << 3 ) + fetch_pte_base( ) };
			if ( !pte_addr ) {
				std::wcout << "--+ invalid pte addr for max discard" << std::endl;
			}

			for ( auto ctx{ pte_addr }; ctx < pte_addr + ( ( driver_bytes.size( ) + 0xfff ) >> 12 ); ctx += 0x8 ) {
				auto page_fn{ call< std::ptrdiff_t >( fetch_get_page_addr( ), fetch_system_partition( ), 0, 0x8 ) };
				if ( !page_fn ) {
					std::wcout << "--+ failed to get page frame number" << std::endl;
					continue;
				}
				
				auto page_id{ fetch_pfn_database( ) + ( page_fn * 0x30 ) };
				if ( !page_id ) {
					std::wcout << "--+ failed to get page index" << std::endl;
					continue;
				}

				if ( !write< std::ptrdiff_t >( ctx, valid | writable | global | dirty | access )
				  || !write< std::ptrdiff_t >( ctx + 0x2, page_fn ) )
					continue;
				
				call< std::ptrdiff_t >( fetch_init_pfn_addr( ), page_id, ctx, 0x4, 0x4 );
			}

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

			if ( !unload_signed( m_registry ) ) {
				std::wcerr << "--+ failed to unload mapped driver" << std::endl;
				return;
			}
		}
	private:
		std::wstring m_path, m_registry;
	};
}
