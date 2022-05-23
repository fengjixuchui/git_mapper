#pragma once

namespace nt {
	const enum info_type_t : std::int32_t {
		module_info = 0x0000000b,
		handle_info = 0x00000010,
		extended_info = 0x00000040
	};

	const enum page_prot_t : std::int32_t {
		no_access = 0x00000001,
		read_only = 0x00000002,
		read_write = 0x00000004,
		write_copy = 0x00000008,
		execute = 0x00000010,
		execute_read = 0x00000020,
		execute_read_write = 0x00000040,
		execute_write_copy = 0x00000080
	};

	const enum mem_flag_t : std::int32_t {
		commit = 0x00001000,
		reserve = 0x00002000,
		physical = 0x00400000,
		decommit = 0x00004000,
		release = 0x00008000,
		free = 0x00010000
	};

	[[ nodiscard ]]
	const std::uint8_t sys_info(
		const std::int32_t type,
		const std::ptrdiff_t buffer,
		const std::size_t size
	) {
		if ( !type || !buffer || !size )
			return 0;

		using call_t = std::int32_t( __stdcall* )( std::int32_t, 
			std::ptrdiff_t, std::size_t, std::size_t* );
		return !ptr< call_t >( &NtQuerySystemInformation )( type, buffer, size, 0 );
	}

	template< typename type_t >
	[[ nodiscard ]]
	const std::uint8_t io_ctl(
		const std::ptrdiff_t device,
		const type_t* buffer
	) {
		if ( !device || !buffer )
			return 0;

		using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, std::int32_t, const type_t*, 
			std::int32_t, std::ptrdiff_t, std::int32_t, std::ptrdiff_t, std::int32_t );
		return !!ptr< call_t >( &DeviceIoControl )( device, 0x80862007, buffer, sizeof( type_t ), 0, 0, 0, 0 );
	}

	[[ nodiscard ]]
	const std::ptrdiff_t mem_alloc(
		const std::ptrdiff_t address,
		const std::size_t size,
		const std::int32_t type,
		const std::int32_t protect
	) {
		if ( !size || !type || !protect )
			return 0;

		using call_t = std::ptrdiff_t( __stdcall* )( std::ptrdiff_t,
			std::size_t, std::int32_t, std::int32_t );
		return ptr< call_t >( &VirtualAlloc )( address, size, type, protect );
	}

	const std::uint8_t mem_free(
		const std::ptrdiff_t address,
		const std::size_t size,
		const std::int32_t type
	) {
		if ( !address || !type )
			return 0;

		using call_t = std::int32_t( __stdcall* )( std::ptrdiff_t, std::size_t, std::int32_t );
		return !!ptr< call_t >( &VirtualFree )( address, size, type );
	}

	[[ nodiscard ]]
	const std::map< std::wstring, std::ptrdiff_t >fetch_kernel_modules( ) {
		auto pool = mem_alloc( 0, 0xffffff, mem_flag_t::commit
			| mem_flag_t::reserve, page_prot_t::execute_read_write );
		if ( !pool )
			return { };

		struct rtl_pe_t {
			std::int8_t m_pad0[16];
			std::ptrdiff_t m_ptr;
			std::uint32_t m_size;
			std::uint8_t m_pad1[10];
			std::uint16_t m_name_offset;
			char m_name[256];
		};

		struct rtl_header_t {
			std::uint32_t m_length;
			rtl_pe_t m_mods[1];
		};

		if ( !sys_info( info_type_t::module_info, pool, 0xffffff ) ) {
			mem_free( pool, 0xffffff, mem_flag_t::release );
			return { };
		}

		auto images = ptr< rtl_header_t* >( pool );
		if ( !images ) {
			mem_free( pool, 0xffffff, mem_flag_t::release );
			return { };
		}

		std::map< std::wstring, std::ptrdiff_t >map{ };

		for ( std::size_t i{ }; i < images->m_length; i++ ) {
			const auto ctx{ images->m_mods[ i ] };
			if ( !ctx.m_name )
				continue;

			std::string name{ ctx.m_name + ctx.m_name_offset };
			if ( name.empty( ) )
				continue;
			map.emplace( std::wstring{ name.begin( ), name.end( ) - 4 }, ctx.m_ptr );
		}

		mem_free( pool, 0xffffff, mem_flag_t::release );
		return map;
	}

	[[ nodiscard ]]
	const std::map< std::wstring, std::ptrdiff_t >fetch_module_exports(
		const std::wstring_view module
	) {
		auto images{ fetch_kernel_modules( ) };
		if ( images.empty( ) )
			return { };


	}

	// GetKernelModuleExport
	// WriteToReadOnlyMemory
}