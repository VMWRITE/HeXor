#pragma once
#include <cstdint>
#ifdef _WIN64
#include <emmintrin.h>
#endif

namespace LLVM
{
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	constexpr uint64_t xor_fnv1a( const char *s, uint64_t h = 14695981039346656037ull )
	{
		return ( *s == 0 ) ? h : xor_fnv1a( s + 1, ( h ^ static_cast< uint64_t >( *s ) ) * 1099511628211ull );
	}

	constexpr uint64_t xor_ct_rotl64( uint64_t x, int k ) { return ( x << k ) | ( x >> ( 64 - k ) ); }

	template <uint64_t a, uint64_t b, uint64_t c, uint64_t d>
	constexpr uint64_t xor_xorshift256( )
	{
		uint64_t s[4] = { a, b, c, d };
		s[2] ^= s[0]; s[3] ^= s[1]; s[1] ^= s[2]; s[0] ^= s[3];
		s[2] ^= s[1] << 17; s[3] = xor_ct_rotl64( s[3], 45 );
		return xor_ct_rotl64( s[0] + s[3], 23 ) + s[0];
	}

	constexpr uint64_t xor_seed_base( ) { return xor_fnv1a( __TIME__ __DATE__ __FILE__ ); }

#define XOR_SEED ( LLVM::xor_seed_base( ) + __COUNTER__ * 0x9E3779B97F4A7C15ull )
#define XOR_RND LLVM::xor_xorshift256<XOR_SEED, XOR_SEED + 1, XOR_SEED + 2, XOR_SEED + 3>()

	enum class EncodingAlgo : uint8_t { HEX, BASE64, RC4, XOR_STREAM, CUSTOM85, COUNT };

	template<uint64_t Key> constexpr EncodingAlgo select_encoding( ) { return static_cast< EncodingAlgo >( ( Key >> 48 ) % static_cast< uint8_t >( EncodingAlgo::COUNT ) ); }

	struct HexEnc
	{
		static constexpr int size( int n ) { return n * 2; }
		static __forceinline constexpr char hex( uint8_t v ) { return "0123456789abcdef"[v & 0xF]; }
		static __forceinline uint8_t unhex( char c ) { return c >= '0' && c <= '9' ? uint8_t( c - '0' ) : c >= 'a' && c <= 'f' ? uint8_t( c - 'a' + 10 ) : c >= 'A' && c <= 'F' ? uint8_t( c - 'A' + 10 ) : 0; }
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { for ( int i = 0; i < N; i++ ) { out[i * 2] = hex( in[i] >> 4 ); out[i * 2 + 1] = hex( in[i] & 0xF ); } }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { for ( int i = 0; i < N; i++ ) out[i] = uint8_t( ( unhex( in[i * 2] ) << 4 ) | unhex( in[i * 2 + 1] ) ); }
	};

	struct B64Enc
	{
		static constexpr int size( int n ) { return ( ( n + 2 ) / 3 ) * 4; }
		static constexpr char tbl[ ] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		static __forceinline constexpr uint8_t unb64( char c ) { if ( c >= 'A' && c <= 'Z' ) return uint8_t( c - 'A' ); if ( c >= 'a' && c <= 'z' ) return uint8_t( c - 'a' + 26 ); if ( c >= '0' && c <= '9' ) return uint8_t( c - '0' + 52 ); if ( c == '+' ) return 62; if ( c == '/' ) return 63; return 0; }
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { int j = 0; for ( int i = 0; i < N; i += 3 ) { uint32_t v = uint32_t( in[i] ) << 16; if ( i + 1 < N ) v |= uint32_t( in[i + 1] ) << 8; if ( i + 2 < N ) v |= in[i + 2]; out[j++] = tbl[( v >> 18 ) & 0x3F]; out[j++] = tbl[( v >> 12 ) & 0x3F]; out[j++] = ( i + 1 < N ) ? tbl[( v >> 6 ) & 0x3F] : '='; out[j++] = ( i + 2 < N ) ? tbl[v & 0x3F] : '='; } }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { int j = 0; for ( int i = 0; i < size( N ) && j < N; i += 4 ) { uint32_t v = ( uint32_t( unb64( in[i] ) ) << 18 ) | ( uint32_t( unb64( in[i + 1] ) ) << 12 ) | ( uint32_t( unb64( in[i + 2] ) ) << 6 ) | unb64( in[i + 3] ); if ( j < N ) out[j++] = uint8_t( v >> 16 ); if ( j < N ) out[j++] = uint8_t( v >> 8 ); if ( j < N ) out[j++] = uint8_t( v ); } }
	};

	template<uint64_t Key> struct RC4Enc
	{
		static constexpr int size( int n ) { return n * 2; }
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { uint8_t t[N]; uint64_t s = Key; for ( int i = 0; i < N; i++ ) { s = s * 6364136223846793005ull + 1442695040888963407ull; t[i] = uint8_t( in[i] ^ uint8_t( s >> 56 ) ); } HexEnc::enc<N>( t, out ); }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { HexEnc::dec<N>( in, out ); uint64_t s = Key; for ( int i = 0; i < N; i++ ) { s = s * 6364136223846793005ull + 1442695040888963407ull; out[i] ^= uint8_t( s >> 56 ); } }
	};

	template<uint64_t Key> struct XorEnc
	{
		static constexpr int size( int n ) { return n * 2; }
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { uint8_t t[N]; uint64_t s = Key; for ( int i = 0; i < N; i++ ) { s = s * 0x5851F42D4C957F2Dull + 0x14057B7EF767814Full; t[i] = uint8_t( in[i] ^ uint8_t( s >> 56 ) ); } HexEnc::enc<N>( t, out ); }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { HexEnc::dec<N>( in, out ); uint64_t s = Key; for ( int i = 0; i < N; i++ ) { s = s * 0x5851F42D4C957F2Dull + 0x14057B7EF767814Full; out[i] ^= uint8_t( s >> 56 ); } }
	};

	template<uint64_t Key> struct C85Enc
	{
		static constexpr int size( int n ) { return ( ( n + 3 ) / 4 ) * 5; }
		static constexpr uint8_t off = uint8_t( 33 + ( Key & 0x1F ) );
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { int j = 0; for ( int i = 0; i < N; i += 4 ) { uint32_t v = 0; for ( int k = 0; k < 4 && i + k < N; k++ ) v = ( v << 8 ) | in[i + k]; for ( int k = 4; k >= 0; k-- ) { out[j + k] = char( off + ( v % 85 ) ); v /= 85; } j += 5; } }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { int j = 0; for ( int i = 0; i < size( N ) && j < N; i += 5 ) { uint32_t v = 0; for ( int k = 0; k < 5; k++ ) v = v * 85 + uint32_t( uint8_t( in[i + k] ) - off ); for ( int k = 3; k >= 0 && j < N; k-- ) out[j++] = uint8_t( v >> ( k * 8 ) ); } }
	};

	template<uint64_t Key, EncodingAlgo Algo> struct EncSel
	{
		static constexpr int size( int n ) { if constexpr ( Algo == EncodingAlgo::BASE64 ) return B64Enc::size( n ); else if constexpr ( Algo == EncodingAlgo::CUSTOM85 ) return C85Enc<Key>::size( n ); else return HexEnc::size( n ); }
		template<int N> static __forceinline constexpr void enc( const uint8_t *in, char *out ) { if constexpr ( Algo == EncodingAlgo::HEX ) HexEnc::enc<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::BASE64 ) B64Enc::enc<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::RC4 ) RC4Enc<Key>::enc<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::XOR_STREAM ) XorEnc<Key>::enc<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::CUSTOM85 ) C85Enc<Key>::enc<N>( in, out ); }
		template<int N> static __forceinline void dec( const char *in, uint8_t *out ) { if constexpr ( Algo == EncodingAlgo::HEX ) HexEnc::dec<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::BASE64 ) B64Enc::dec<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::RC4 ) RC4Enc<Key>::dec<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::XOR_STREAM ) XorEnc<Key>::dec<N>( in, out ); else if constexpr ( Algo == EncodingAlgo::CUSTOM85 ) C85Enc<Key>::dec<N>( in, out ); }
	};

	enum class VmOp : uint8_t
	{
		XOR_KEY, ROL, ROR, ADD, SUB, NOT_XOR, SWAP_NIB, MUL_ODD,
		XOR_ROL, XOR_ROR, ADD_XOR, BIT_REV, XNOR, ADD_ROL, SUB_ROR, CHAIN_XOR,
		MBA_ADD, MBA_SUB, MBA_XOR, MBA_XOR_COMPLEX,
		COUNT
	};

	namespace ByteOps
	{
		constexpr uint8_t rol8( uint8_t v, int s ) { s &= 7; return uint8_t( ( v << s ) | ( v >> ( 8 - s ) ) ); }
		constexpr uint8_t ror8( uint8_t v, int s ) { s &= 7; return uint8_t( ( v >> s ) | ( v << ( 8 - s ) ) ); }
		constexpr uint8_t rev( uint8_t v ) { v = uint8_t( ( ( v & 0xF0 ) >> 4 ) | ( ( v & 0x0F ) << 4 ) ); v = uint8_t( ( ( v & 0xCC ) >> 2 ) | ( ( v & 0x33 ) << 2 ) ); return uint8_t( ( ( v & 0xAA ) >> 1 ) | ( ( v & 0x55 ) << 1 ) ); }
		constexpr uint8_t inv( uint8_t a ) { uint8_t x = a; for ( int i = 0; i < 5; i++ ) x = uint8_t( x * ( 2 - a * x ) ); return x; }

		constexpr uint8_t add_mba( uint8_t x, uint8_t y ) { return uint8_t( ( x ^ y ) + ( ( x & y ) << 1 ) ); }
		constexpr uint8_t sub_mba( uint8_t x, uint8_t y ) { return uint8_t( ( x ^ y ) - ( ( ~x & y ) << 1 ) ); }
		constexpr uint8_t xor_mba( uint8_t x, uint8_t y ) { return uint8_t( ( x | y ) - ( x & y ) ); }
		constexpr uint8_t xor_complex( uint8_t x, uint8_t k )
		{
			uint8_t or_val = x | k;
			uint8_t and_val = x & k;
			return uint8_t( ( or_val ^ and_val ) + ( ( or_val & and_val ) << 1 ) - ( and_val << 1 ) );
		}
	}

	template <uint64_t Key> struct VmObfuscator
	{
		static constexpr auto op = static_cast< VmOp >( ( Key >> 8 ) % uint8_t( VmOp::COUNT ) );
		static constexpr uint8_t k8 = uint8_t( Key ), k8_2 = uint8_t( Key >> 16 ), mk = uint8_t( Key | 1 ), mi = ByteOps::inv( mk );
		static constexpr int sh = int( ( ( Key >> 24 ) % 7 ) + 1 );

		static __forceinline constexpr uint8_t enc( uint8_t v, int i, uint8_t p = 0 )
		{
			uint8_t k = uint8_t( k8 ^ i ), k2 = uint8_t( k8_2 ^ ( i * 3 ) );
			if constexpr ( op == VmOp::XOR_KEY ) return uint8_t( v ^ k );
			else if constexpr ( op == VmOp::ROL ) return ByteOps::rol8( v, sh ) ^ k;
			else if constexpr ( op == VmOp::ROR ) return ByteOps::ror8( v, sh ) ^ k;
			else if constexpr ( op == VmOp::ADD ) return uint8_t( v + k );
			else if constexpr ( op == VmOp::SUB ) return uint8_t( v - k );
			else if constexpr ( op == VmOp::NOT_XOR ) return uint8_t( ~v ^ k );
			else if constexpr ( op == VmOp::SWAP_NIB ) return uint8_t( ( ( v << 4 ) | ( v >> 4 ) ) ^ k );
			else if constexpr ( op == VmOp::MUL_ODD ) return uint8_t( v * mk + k );
			else if constexpr ( op == VmOp::XOR_ROL ) return ByteOps::rol8( uint8_t( v ^ k ), sh );
			else if constexpr ( op == VmOp::XOR_ROR ) return ByteOps::ror8( uint8_t( v ^ k ), sh );
			else if constexpr ( op == VmOp::ADD_XOR ) return uint8_t( ( v + k ) ^ k2 );
			else if constexpr ( op == VmOp::BIT_REV ) return uint8_t( ByteOps::rev( v ) ^ k );
			else if constexpr ( op == VmOp::XNOR ) return uint8_t( ~( v ^ k ) );
			else if constexpr ( op == VmOp::ADD_ROL ) return ByteOps::rol8( uint8_t( v + k ), sh );
			else if constexpr ( op == VmOp::SUB_ROR ) return ByteOps::ror8( uint8_t( v - k ), sh );
			else if constexpr ( op == VmOp::CHAIN_XOR ) return uint8_t( v ^ k ^ p );
			else if constexpr ( op == VmOp::MBA_ADD ) return ByteOps::add_mba( v, k );
			else if constexpr ( op == VmOp::MBA_SUB ) return ByteOps::sub_mba( v, k );
			else if constexpr ( op == VmOp::MBA_XOR ) return ByteOps::xor_mba( v, k );
			else if constexpr ( op == VmOp::MBA_XOR_COMPLEX ) return ByteOps::xor_complex( v, k );
			return v;
		}
		static __forceinline constexpr uint8_t dec( uint8_t v, int i, uint8_t p = 0 )
		{
			uint8_t k = uint8_t( k8 ^ i ), k2 = uint8_t( k8_2 ^ ( i * 3 ) );
			if constexpr ( op == VmOp::XOR_KEY ) return uint8_t( v ^ k );
			else if constexpr ( op == VmOp::ROL ) return ByteOps::ror8( uint8_t( v ^ k ), sh );
			else if constexpr ( op == VmOp::ROR ) return ByteOps::rol8( uint8_t( v ^ k ), sh );
			else if constexpr ( op == VmOp::ADD ) return uint8_t( v - k );
			else if constexpr ( op == VmOp::SUB ) return uint8_t( v + k );
			else if constexpr ( op == VmOp::NOT_XOR ) return uint8_t( ~( v ^ k ) );
			else if constexpr ( op == VmOp::SWAP_NIB ) { auto t = uint8_t( v ^ k ); return uint8_t( ( t << 4 ) | ( t >> 4 ) ); }
			else if constexpr ( op == VmOp::MUL_ODD ) return uint8_t( ( v - k ) * mi );
			else if constexpr ( op == VmOp::XOR_ROL ) return uint8_t( ByteOps::ror8( v, sh ) ^ k );
			else if constexpr ( op == VmOp::XOR_ROR ) return uint8_t( ByteOps::rol8( v, sh ) ^ k );
			else if constexpr ( op == VmOp::ADD_XOR ) return uint8_t( ( v ^ k2 ) - k );
			else if constexpr ( op == VmOp::BIT_REV ) return ByteOps::rev( uint8_t( v ^ k ) );
			else if constexpr ( op == VmOp::XNOR ) return uint8_t( ~v ^ k );
			else if constexpr ( op == VmOp::ADD_ROL ) return uint8_t( ByteOps::ror8( v, sh ) - k );
			else if constexpr ( op == VmOp::SUB_ROR ) return uint8_t( ByteOps::rol8( v, sh ) + k );
			else if constexpr ( op == VmOp::CHAIN_XOR ) return uint8_t( v ^ k ^ p );
			// MBA Operations (inverse)
			else if constexpr ( op == VmOp::MBA_ADD ) return ByteOps::sub_mba( v, k );
			else if constexpr ( op == VmOp::MBA_SUB ) return ByteOps::add_mba( v, k );
			else if constexpr ( op == VmOp::MBA_XOR ) return ByteOps::xor_mba( v, k );
			else if constexpr ( op == VmOp::MBA_XOR_COMPLEX ) return ByteOps::xor_complex( v, k );
			return v;
		}
	};

	template <int Size, uint64_t Key> struct BytePermutation
	{
		static constexpr void init( uint8_t *p ) { for ( int i = 0; i < Size; i++ ) p[i] = uint8_t( i ); uint64_t r = Key; for ( int i = Size - 1; i > 0; i-- ) { r = r * 6364136223846793005ull + 1442695040888963407ull; int j = int( ( r >> 33 ) % uint64_t( i + 1 ) ); uint8_t t = p[i]; p[i] = p[j]; p[j] = t; } }
		static constexpr void inv( const uint8_t *p, uint8_t *o ) { for ( int i = 0; i < Size; i++ ) o[p[i]] = uint8_t( i ); }
	};

	template <int _size, uint64_t K1, uint64_t K2, uint64_t K3, uint64_t K4, uint64_t K5, uint64_t K6, uint64_t K7, uint64_t K8,
		uint64_t J1, uint64_t J2, uint64_t J3, uint64_t J4, uint64_t EK, typename T>
	class HeXor
	{
	public:
		__forceinline constexpr HeXor( T *data ) { encrypt_data( data ); }
		__forceinline T *get( ) { return reinterpret_cast< T * >( _storage ); }
		__forceinline int size( ) { return _size; }
		__forceinline  T *decrypt( ) { if ( _encrypted ) decrypt_data( ); return reinterpret_cast< T * >( _storage ); }
		__forceinline void clear( ) { for ( int i = 0; i < StorageSize; i++ ) _storage[i] = 0; _encrypted = true; }
		__forceinline operator T *( ) { return decrypt( ); }

	private:
		static constexpr EncodingAlgo EncAlgo = select_encoding<EK>( );
		using Enc = EncSel<EK, EncAlgo>;
		static constexpr int DataEncSize = Enc::size( _size ), ChkEncSize = Enc::size( 4 ), StorageSize = DataEncSize + ChkEncSize;

		using L1 = VmObfuscator<K1>; using L2 = VmObfuscator<K2>; using L3 = VmObfuscator<K3>; using L4 = VmObfuscator<K4>;
		using L5 = VmObfuscator<K5>; using L6 = VmObfuscator<K6>; using L7 = VmObfuscator<K7>; using L8 = VmObfuscator<K8>;

		static constexpr uint64_t PK = K1 ^ K2 ^ K3 ^ K4, CK = K5 ^ K6 ^ K7 ^ K8;
		static constexpr uint8_t IV = uint8_t( ( K1 + K2 + K3 + K4 ) & 0xFF );

		static __forceinline constexpr uint32_t chksum( const uint8_t *d, int n ) { uint32_t h = uint32_t( CK ); for ( int i = 0; i < n; i++ ) { h ^= d[i]; h = ( h << 5 ) | ( h >> 27 ); h *= 0x85EBCA6B; } return h; }

		__forceinline constexpr void encrypt_data( T *data )
		{
			uint8_t temp[_size]{}, perm[_size]{};
			BytePermutation<_size, PK>::init( perm );
			for ( int i = 0; i < _size; i++ ) temp[perm[i]] = uint8_t( data[i] );
			uint8_t prev = IV;
			for ( int i = 0; i < _size; i++ )
			{
				uint8_t b = temp[i];
				b = L1::enc( b, i, prev ); b = L2::enc( b, i * 2, prev ); b = L3::enc( b, i * 3, prev ); b = L4::enc( b, i * 5, prev );
				b = L5::enc( b, i * 7, prev ); b = L6::enc( b, i * 11, prev ); b = L7::enc( b, i * 13, prev ); b = L8::enc( b, i * 17, prev );
				prev = b; temp[i] = b;
			}
			uint32_t c = chksum( temp, _size );
			uint8_t cb[4] = { uint8_t( c ), uint8_t( c >> 8 ), uint8_t( c >> 16 ), uint8_t( c >> 24 ) };
			Enc::enc<_size>( temp, _storage );
			Enc::enc<4>( cb, _storage + DataEncSize );
			_encrypted = true;
		}

		__forceinline void decrypt_data( )
		{
			uint8_t temp[_size]{}, perm[_size]{};
			BytePermutation<_size, PK>::init( perm );
			Enc::dec<_size>( _storage, temp );
			uint8_t cb[4]{}; Enc::dec<4>( _storage + DataEncSize, cb );
			uint32_t stored = uint32_t( cb[0] ) | ( uint32_t( cb[1] ) << 8 ) | ( uint32_t( cb[2] ) << 16 ) | ( uint32_t( cb[3] ) << 24 );
			uint32_t comp = chksum( temp, _size );
			if ( stored != comp ) { for ( int i = 0; i < _size; i++ ) _storage[i] = '\0'; _encrypted = false; return; }
			uint8_t pc[_size + 1]{}; pc[0] = IV; for ( int i = 0; i < _size; i++ ) pc[i + 1] = temp[i];
			for ( int i = 0; i < _size; i++ )
			{
				uint8_t b = temp[i], p = pc[i];
				b = L8::dec( b, i * 17, p ); b = L7::dec( b, i * 13, p ); b = L6::dec( b, i * 11, p ); b = L5::dec( b, i * 7, p );
				b = L4::dec( b, i * 5, p ); b = L3::dec( b, i * 3, p ); b = L2::dec( b, i * 2, p ); b = L1::dec( b, i, p );
				temp[i] = b;
			}
			for ( int i = 0; i < _size; i++ ) _storage[i] = char( temp[perm[i]] );
			for ( int i = _size; i < StorageSize; i++ ) _storage[i] = '\0';
			_encrypted = false;
		}

		char _storage[StorageSize]{};
		bool _encrypted = true;
	};
}

#define HeXor(str) []() { \
		constexpr static auto crypted = LLVM::HeXor \
			<sizeof(str) / sizeof(str[0]), \
			XOR_RND, XOR_RND, XOR_RND, XOR_RND, XOR_RND, XOR_RND, XOR_RND, XOR_RND, \
			XOR_RND, XOR_RND, XOR_RND, XOR_RND, XOR_RND, \
			LLVM::clean_type<decltype(str[0])>>((LLVM::clean_type<decltype(str[0])>*)str); \
				return crypted; }()
