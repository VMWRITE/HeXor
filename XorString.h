#pragma once
#include "Poly.h"

namespace WRTH
{
	template<class _Ty>
	using clean_type = typename std::remove_const_t<std::remove_reference_t<_Ty>>;

	template <int _size, char _key1, char _key2, typename T>
	class HeXor
	{
	public:
		__forceinline constexpr HeXor( T *data )
		{
			crypt( data );
		}

		__forceinline T *get( )
		{
			return _storage;
		}

		__forceinline int size( ) // (w)char count
		{
			return _size;
		}

		__forceinline  char key( )
		{
			return _key1;
		}

		__forceinline  T *encrypt( )
		{
			if ( !isEncrypted( ) )
				crypt( _storage );

			return _storage;
		}

		__forceinline  T *decrypt( )
		{
			if ( isEncrypted( ) )
				decrypt( _storage );

			return _storage;
		}

		__forceinline bool isEncrypted( )
		{
			return _storage[ _size * 2 - 1 ] == '0' && _storage[ _size * 2 - 2 ] == '0';
		}

		__forceinline void clear( )
		{
			for ( int i = 0; i < _size; i++ )
			{
				_storage[ i ] = 0;
			}
		}

		__forceinline operator T *( )
		{
			decrypt( );

			return _storage;
		}

	private:

		unsigned char encode( char x )
		{
			if ( x >= '0' && x <= '9' )         /* 0-9 is offset by hex 30 */
				return ( x - 0x30 );
			else if ( x >= 'a' && x <= 'f' )    /* a-f offset by hex 57 */
				return( x - 0x57 );
			else if ( x >= 'A' && x <= 'F' )    /* A-F offset by hex 37 */
				return( x - 0x37 );
		}

		__forceinline constexpr void crypt( T *data )
		{

			for ( int i = 0; i < _size; i++ )
			{
				auto enc1 = "0123456789abcdef"[ ( ( data[ i ] ) >> 4 ) & 0x0f ];
				auto enc2 = "0123456789abcdef"[ ( data[ i ] ) & 0x0f ];

				if ( enc1 == '0' && enc2 == '0' )
				{
					_storage[ i * 2 ] = '0';
					_storage[ i * 2 + 1 ] = '0';
				}
				else
				{
					_storage[ i * 2 ] = "0123456789abcdef"[ ( ( data[ i ] ^ ( _key1 + i % ( 1 + _key2 ) ) ) >> 4 ) & 0x0f ];
					_storage[ i * 2 + 1 ] = "0123456789abcdef"[ ( data[ i ] ^ ( _key1 + i % ( 1 + _key2 ) ) ) & 0x0f ];
				}
			}
		}

		__forceinline constexpr void decrypt( T *data )
		{

			for ( int i = 0; i < _size; i++ )
			{

				_storage[ i ] = ( ( ( encode( data[ i * 2 ] ) * 16 ) & 0xF0 ) + ( encode( data[ i * 2 + 1 ] ) & 0x0F ) );

				_storage[ i ] = data[ i ] ^ ( _key1 + i % ( 1 + _key2 ) );

			}

			for ( int i = _size - 1; i < _size * 2; i++ )
			{
				_storage[ i ] = '\0';
			}
		}

		T _storage[ _size * 2 ] {};
	};
}

#define HeXor(str) XorWithKey(str, poly_random_mm(5000000, 999999999), poly_random_mm(500000, 99999999))
#define XorWithKey(str, key1, key2) []() { \
			constexpr static auto crypted = WRTH::HeXor \
				<sizeof(str) / sizeof(str[0]), key1, key2, WRTH::clean_type<decltype(str[0])>>((WRTH::clean_type<decltype(str[0])>*)str); \
					return crypted; }()
