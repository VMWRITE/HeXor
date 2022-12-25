#define NOMINMAX

#include <cmath>
#include <limits>
#include <signal.h>

#undef min
#undef max

#define M_PI       3.14159265358979323846   // pi


// ================
// COMPILE-TIME RNG
// ================

struct poly
{
private:
	// common types
	typedef unsigned long long ull;
	typedef unsigned int ui;

	// arithmetic simplification functions
	static constexpr ull sq( ull x ) { return x * x; }
	static constexpr ull sm( ull x ) { return sq( x ) + x; }
	static constexpr ull sh( ull x ) { return ( x >> 32 ) | ( x << 32 ); }

public:
	// normal prng's are hard to use here, since we can't easily modify our state
	// we need to use a counter-based rng, to use __COUNTER__ as our state instead
	// https://en.wikipedia.org/wiki/Counter-based_random_number_generator_(CBRNG)
	// we use Widynski's Squares method to achieve this: https://arxiv.org/abs/2004.06278
	static constexpr ui Widynski_Squares( ull count, ull seed )
	{
		unsigned long long cs = ( count + 1 ) * seed;
		return ( sq( sh( sq( sh( sm( cs ) ) ) + cs + seed ) ) + cs ) >> 32;
	}

	// we use Box-Muller as our method to obtain a normal distribution
	// we add the lowest positive double value to prevent log(0) from being run
	static double BoxMuller( double a, double b, double sigma, double mu )
	{
		const double e = std::numeric_limits<double>::min( );
		return sqrt( -2.0 * log( a + e ) ) * cos( 2.0 * M_PI * b ) * sigma + mu;
	}

	// we define our seed based off of the __DATE__ and __TIME__ macros
	// this allows us to have different compile-time seed values
	static constexpr ull Day =
		( __DATE__[ 5 ] - '0' ) +
		( __DATE__[ 4 ] == ' ' ? 0 : __DATE__[ 4 ] - '0' ) * 10;

	static constexpr ull Month =
		( __DATE__[ 1 ] == 'a' && __DATE__[ 2 ] == 'n' ) * 1 +
		( __DATE__[ 2 ] == 'b' ) * 2 +
		( __DATE__[ 1 ] == 'a' && __DATE__[ 2 ] == 'r' ) * 3 +
		( __DATE__[ 1 ] == 'p' && __DATE__[ 2 ] == 'r' ) * 4 +
		( __DATE__[ 2 ] == 'y' ) * 5 +
		( __DATE__[ 1 ] == 'u' && __DATE__[ 2 ] == 'n' ) * 6 +
		( __DATE__[ 2 ] == 'l' ) * 7 +
		( __DATE__[ 2 ] == 'g' ) * 8 +
		( __DATE__[ 2 ] == 'p' ) * 9 +
		( __DATE__[ 2 ] == 't' ) * 10 +
		( __DATE__[ 2 ] == 'v' ) * 11 +
		( __DATE__[ 2 ] == 'c' ) * 12;

	static constexpr ull Year =
		( __DATE__[ 9 ] - '0' ) +
		( __DATE__[ 10 ] - '0' ) * 10;

	static constexpr ull Time =
		( __TIME__[ 0 ] - '0' ) * 1 +
		( __TIME__[ 1 ] - '0' ) * 10 +
		( __TIME__[ 3 ] - '0' ) * 100 +
		( __TIME__[ 4 ] - '0' ) * 1000 +
		( __TIME__[ 6 ] - '0' ) * 10000 +
		( __TIME__[ 7 ] - '0' ) * 100000;

	#ifndef __POLY_RANDOM_SEED__
	static constexpr ull Seed =
		Time +
		100000ll * Day +
		10000000ll * Month +
		1000000000ll * Year;
	#else
	static constexpr ull Seed = __POLY_RANDOM_SEED__;
	#endif
};

// =====================
// POLYMORPHIC FUNCTIONS
// =====================

// various random types
#define poly_uint() (poly::Widynski_Squares(__COUNTER__, poly::Seed))
#define poly_int() ((int)poly_uint())
#define poly_ull() (((unsigned long long)poly_int() << 32) ^ poly_int())
#define poly_ll() ((long long)poly_ull())
#define poly_float() (static_cast<float>(poly_uint()) / static_cast<float>(UINT_MAX))
#define poly_double() (static_cast<double>(poly_ull()) / static_cast<double>(ULLONG_MAX))

// random number modulo max
#define poly_random(max) (poly_uint() % max)
#define poly_random_mm(min, max) (min + poly_uint() % max)
