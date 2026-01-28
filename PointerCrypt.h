#pragma once
#include <cstdint>
#include <intrin.h>
#include <emmintrin.h> 

consteval uint64_t fnv1impl( uint64_t h, const char *s )
{
	return ( *s == 0 )
		? h
		: fnv1impl( ( h * 1099511628211ull ) ^ static_cast< uint64_t >( *s ), s + 1 );
}

consteval uint64_t fnv1( const char *s )
{
	return fnv1impl( 14695981039346656037ull, s );
}

template <typename T>
consteval uint64_t type_hash( )
{
	return fnv1( __FUNCSIG__ );
}

template <uint64_t Seed>
struct KeyGen
{
	static constexpr uint64_t K1 = Seed ^ 0xDEADBEEFCAFEBABEull;
	static constexpr uint64_t K2 = ( Seed * 0x9E3779B97F4A7C15ull ) ^ 0xC6A4A7935BD1E995ull;
	static constexpr uint64_t K3 = ( ( Seed >> 32 ) | ( Seed << 32 ) ) ^ 0x94D049BB133111EBull;
	static constexpr uint64_t K4 = ( Seed ^ ( Seed >> 33 ) ) * 0xFF51AFD7ED558CCDull;
};

namespace HiddenPtrOps
{
	constexpr int MaxShift = ( sizeof( uintptr_t ) * 8 ) - 1; 

#ifdef _WIN64
	namespace SSE2
	{
		__forceinline uintptr_t xor_sse( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_xor_si128( v, k ) ) );
		}

		__forceinline uintptr_t add_sse( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_add_epi64( v, k ) ) );
		}

		__forceinline uintptr_t sub_sse( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_sub_epi64( v, k ) ) );
		}

		__forceinline uintptr_t xor_add_sse( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			__m128i k2 = _mm_cvtsi64_si128( static_cast< long long >( key >> 32 ) );
			__m128i xored = _mm_xor_si128( v, k );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_add_epi64( xored, k2 ) ) );
		}

		__forceinline uintptr_t xor_add_sse_inv( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			__m128i k2 = _mm_cvtsi64_si128( static_cast< long long >( key >> 32 ) );
			__m128i subbed = _mm_sub_epi64( v, k2 );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_xor_si128( subbed, k ) ) );
		}

		__forceinline uintptr_t complex_sse( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			__m128i k2 = _mm_cvtsi64_si128( static_cast< long long >( key >> 32 ) );
			__m128i k3 = _mm_cvtsi64_si128( static_cast< long long >( key >> 48 ) );
			__m128i added = _mm_add_epi64( v, k );
			__m128i xored = _mm_xor_si128( added, k2 );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_add_epi64( xored, k3 ) ) );
		}

		__forceinline uintptr_t complex_sse_inv( uintptr_t val, uintptr_t key )
		{
			__m128i v = _mm_cvtsi64_si128( static_cast< long long >( val ) );
			__m128i k = _mm_cvtsi64_si128( static_cast< long long >( key ) );
			__m128i k2 = _mm_cvtsi64_si128( static_cast< long long >( key >> 32 ) );
			__m128i k3 = _mm_cvtsi64_si128( static_cast< long long >( key >> 48 ) );
			__m128i subbed = _mm_sub_epi64( v, k3 );
			__m128i xored = _mm_xor_si128( subbed, k2 );
			return static_cast< uintptr_t >( _mm_cvtsi128_si64( _mm_sub_epi64( xored, k ) ) );
		}
	}
#endif

	namespace MBA
	{
		__forceinline uintptr_t add_mba( uintptr_t x, uintptr_t y )
		{
			return ( x ^ y ) + ( ( x & y ) << 1 );
		}

		__forceinline uintptr_t sub_mba( uintptr_t x, uintptr_t y )
		{
			return ( x ^ y ) - ( ( ~x & y ) << 1 );
		}

		__forceinline uintptr_t xor_mba( uintptr_t x, uintptr_t y )
		{
			return ( x | y ) - ( x & y );
		}

		__forceinline uintptr_t xor_complex( uintptr_t x, uintptr_t k )
		{
			uintptr_t or_val = x | k;
			uintptr_t and_val = x & k;
			return ( or_val ^ and_val ) + ( ( or_val & and_val ) << 1 ) - ( and_val << 1 );
		}

		__forceinline uintptr_t affine_mba( uintptr_t x, uintptr_t mult, uintptr_t add_const )
		{
			mult |= 1;
			uintptr_t result = 0;
			for ( int i = 0; i < 64; i++ )
				if ( ( mult >> i ) & 1 )
					result = add_mba( result, x << i );
			return xor_mba( result, add_const );
		}
	}

	__forceinline uintptr_t rotl( uintptr_t val, int shift )
	{
#ifdef _WIN64
		return _rotl64( val, shift );
#else
		return _rotl( static_cast< unsigned long >( val ), shift );
#endif
	}

	__forceinline uintptr_t rotr( uintptr_t val, int shift )
	{
#ifdef _WIN64
		return _rotr64( val, shift );
#else
		return _rotr( static_cast< unsigned long >( val ), shift );
#endif
	}

	__forceinline uintptr_t byteswap( uintptr_t val )
	{
#ifdef _WIN64
		return _byteswap_uint64( val );
#else
		return _byteswap_ulong( static_cast< unsigned long >( val ) );
#endif
	}

	__forceinline uintptr_t mod_inverse( uintptr_t a )
	{
		uintptr_t inv = a;
		for ( int i = 0; i < 6; i++ )
			inv = inv * ( 2 - a * inv );
		return inv;
	}
}

enum class ObfOp : uint8_t
{
	XOR_KEY = 0,
	ADD_KEY,
	SUB_KEY,
	ROTL_XOR,
	ROTR_XOR,
	BYTESWAP_XOR,
	NOT_XOR,
	MUL_ODD,
	MBA_ADD,
	MBA_SUB,
	MBA_XOR,
	MBA_XOR_COMPLEX,
	MBA_AFFINE,
	MBA_LINEAR,
#ifdef _WIN64
	SSE_XOR,
	SSE_ADD,
	SSE_XOR_ADD,
	SSE_COMPLEX,
#endif
	COUNT
};

template <uint64_t Key, uint8_t Op>
struct ObfuscateStep
{
	static constexpr auto op = static_cast< ObfOp >( Op % static_cast< uint8_t >( ObfOp::COUNT ) );
	static constexpr int shift = static_cast< int >( ( Key % HiddenPtrOps::MaxShift ) + 1 );
	static constexpr uintptr_t key = static_cast< uintptr_t >( Key );
	static constexpr uintptr_t key_odd = key | 1;

	static __forceinline uintptr_t encode( uintptr_t val )
	{
		if constexpr ( op == ObfOp::XOR_KEY )
			return val ^ key;
		else if constexpr ( op == ObfOp::ADD_KEY )
			return val + key;
		else if constexpr ( op == ObfOp::SUB_KEY )
			return val - key;
		else if constexpr ( op == ObfOp::ROTL_XOR )
			return HiddenPtrOps::rotl( val, shift ) ^ key;
		else if constexpr ( op == ObfOp::ROTR_XOR )
			return HiddenPtrOps::rotr( val, shift ) ^ key;
		else if constexpr ( op == ObfOp::BYTESWAP_XOR )
			return HiddenPtrOps::byteswap( val ) ^ key;
		else if constexpr ( op == ObfOp::NOT_XOR )
			return ~val ^ key;
		else if constexpr ( op == ObfOp::MUL_ODD )
			return val * key_odd;
		else if constexpr ( op == ObfOp::MBA_ADD )
			return HiddenPtrOps::MBA::add_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_SUB )
			return HiddenPtrOps::MBA::sub_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_XOR )
			return HiddenPtrOps::MBA::xor_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_XOR_COMPLEX )
			return HiddenPtrOps::MBA::xor_complex( val, key );
		else if constexpr ( op == ObfOp::MBA_AFFINE )
			return HiddenPtrOps::MBA::affine_mba( val, key_odd, key >> 32 );
		else if constexpr ( op == ObfOp::MBA_LINEAR )
			return val * key_odd + ( key >> 32 );
#ifdef _WIN64
		else if constexpr ( op == ObfOp::SSE_XOR )
			return HiddenPtrOps::SSE2::xor_sse( val, key );
		else if constexpr ( op == ObfOp::SSE_ADD )
			return HiddenPtrOps::SSE2::add_sse( val, key );
		else if constexpr ( op == ObfOp::SSE_XOR_ADD )
			return HiddenPtrOps::SSE2::xor_add_sse( val, key );
		else if constexpr ( op == ObfOp::SSE_COMPLEX )
			return HiddenPtrOps::SSE2::complex_sse( val, key );
#endif
		return val;
	}

	static __forceinline uintptr_t decode( uintptr_t val )
	{
		if constexpr ( op == ObfOp::XOR_KEY )
			return val ^ key;
		else if constexpr ( op == ObfOp::ADD_KEY )
			return val - key;
		else if constexpr ( op == ObfOp::SUB_KEY )
			return val + key;
		else if constexpr ( op == ObfOp::ROTL_XOR )
			return HiddenPtrOps::rotr( val ^ key, shift );
		else if constexpr ( op == ObfOp::ROTR_XOR )
			return HiddenPtrOps::rotl( val ^ key, shift );
		else if constexpr ( op == ObfOp::BYTESWAP_XOR )
			return HiddenPtrOps::byteswap( val ^ key );
		else if constexpr ( op == ObfOp::NOT_XOR )
			return ~( val ^ key );
		else if constexpr ( op == ObfOp::MUL_ODD )
			return val * HiddenPtrOps::mod_inverse( key_odd );
		else if constexpr ( op == ObfOp::MBA_ADD )
			return HiddenPtrOps::MBA::sub_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_SUB )
			return HiddenPtrOps::MBA::add_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_XOR )
			return HiddenPtrOps::MBA::xor_mba( val, key );
		else if constexpr ( op == ObfOp::MBA_XOR_COMPLEX )
			return HiddenPtrOps::MBA::xor_complex( val, key );
		else if constexpr ( op == ObfOp::MBA_AFFINE )
		{
			uintptr_t t = HiddenPtrOps::MBA::xor_mba( val, key >> 32 );
			return t * HiddenPtrOps::mod_inverse( key_odd );
		}
		else if constexpr ( op == ObfOp::MBA_LINEAR )
			return ( val - ( key >> 32 ) ) * HiddenPtrOps::mod_inverse( key_odd );
#ifdef _WIN64
		else if constexpr ( op == ObfOp::SSE_XOR )
			return HiddenPtrOps::SSE2::xor_sse( val, key );
		else if constexpr ( op == ObfOp::SSE_ADD )
			return HiddenPtrOps::SSE2::sub_sse( val, key );
		else if constexpr ( op == ObfOp::SSE_XOR_ADD )
			return HiddenPtrOps::SSE2::xor_add_sse_inv( val, key );
		else if constexpr ( op == ObfOp::SSE_COMPLEX )
			return HiddenPtrOps::SSE2::complex_sse_inv( val, key );
#endif
		return val;
	}
};

template <uint64_t K1, uint64_t K2, uint64_t K3, uint64_t K4>
class HiddenPtrImpl
{
private:
	volatile uintptr_t encoded;
	volatile uintptr_t checksum;

	static __forceinline uintptr_t compute_checksum( uintptr_t val )
	{
		uintptr_t h = val ^ K1;
		h = HiddenPtrOps::rotl( h, 13 ) * K2;
		h ^= h >> 33;
		h = HiddenPtrOps::rotl( h, 17 ) * K3;
		h ^= h >> 29;
		h *= K4;
		return h;
	}

public:
	__forceinline HiddenPtrImpl( ) noexcept : encoded( 0 ), checksum( 0 ) { }

	__forceinline void set( uintptr_t val ) noexcept
	{
		val = ObfuscateStep<K1, static_cast< uint8_t >( K1 & 0xFF )>::encode( val );
		val = ObfuscateStep<K2, static_cast< uint8_t >( K2 & 0xFF )>::encode( val );
		val = ObfuscateStep<K3, static_cast< uint8_t >( K3 & 0xFF )>::encode( val );
		val = ObfuscateStep<K4, static_cast< uint8_t >( K4 & 0xFF )>::encode( val );
		val = ObfuscateStep<K1 ^ K3, static_cast< uint8_t >( ( K1 ^ K3 ) & 0xFF )>::encode( val );
		val = ObfuscateStep<K2 ^ K4, static_cast< uint8_t >( ( K2 ^ K4 ) & 0xFF )>::encode( val );

		encoded = val;
		checksum = compute_checksum( val );
	}

	__forceinline uintptr_t get( ) const noexcept
	{
		uintptr_t val = encoded;

		if ( checksum != compute_checksum( val ) )
			return 0;

		val = ObfuscateStep<K2 ^ K4, static_cast< uint8_t >( ( K2 ^ K4 ) & 0xFF )>::decode( val );
		val = ObfuscateStep<K1 ^ K3, static_cast< uint8_t >( ( K1 ^ K3 ) & 0xFF )>::decode( val );
		val = ObfuscateStep<K4, static_cast< uint8_t >( K4 & 0xFF )>::decode( val );
		val = ObfuscateStep<K3, static_cast< uint8_t >( K3 & 0xFF )>::decode( val );
		val = ObfuscateStep<K2, static_cast< uint8_t >( K2 & 0xFF )>::decode( val );
		val = ObfuscateStep<K1, static_cast< uint8_t >( K1 & 0xFF )>::decode( val );
		return val;
	}
};

template <typename T>
class HiddenPtr
{
private:
	static constexpr uint64_t Seed = type_hash<T>( );
	using Keys = KeyGen<Seed>;

	HiddenPtrImpl<Keys::K1, Keys::K2, Keys::K3, Keys::K4> impl;

public:
	__forceinline HiddenPtr( ) noexcept { impl.set( 0 ); }
	__forceinline HiddenPtr( T *ptr ) noexcept { impl.set( reinterpret_cast< uintptr_t >( ptr ) ); }
	__forceinline HiddenPtr( std::nullptr_t ) noexcept { impl.set( 0 ); }

	__forceinline void set( T *ptr ) noexcept { impl.set( reinterpret_cast< uintptr_t >( ptr ) ); }
	__forceinline T *get( ) const noexcept { return reinterpret_cast< T * >( impl.get( ) ); }

	__forceinline T *operator->( ) const noexcept { return get( ); }
	__forceinline T &operator*( ) const noexcept { return *get( ); }
	__forceinline operator bool( ) const noexcept { return get( ) != nullptr; }
	__forceinline bool operator==( T *other ) const noexcept { return get( ) == other; }
	__forceinline bool operator!=( T *other ) const noexcept { return get( ) != other; }

	__forceinline HiddenPtr &operator=( T *ptr ) noexcept { set( ptr ); return *this; }
	__forceinline HiddenPtr &operator=( std::nullptr_t ) noexcept { impl.set( 0 ); return *this; }
};
