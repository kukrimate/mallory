// SPDX-License-Identifier: BSD-2-Clause-Patent

#ifndef COMPILER_H_
#define COMPILER_H_

/*
 * These are special ones that get our unit tests in trouble with the
 * compiler optimizer dropping out tests...
 */
#ifdef NONNULL
# undef NONNULL
#endif
#ifdef RETURNS_NONNULL
# undef RETURNS_NONNULL
#endif
#ifdef SHIM_UNIT_TEST
# define NONNULL(first, args...)
# define RETURNS_NONNULL
#else
# define NONNULL(first, args...) __attribute__((__nonnull__(first, ## args)))
#if (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)))
# define RETURNS_NONNULL __attribute__((__returns_nonnull__))
#else
# define RETURNS_NONNULL
#endif
#endif

#ifndef UNUSED
#define UNUSED __attribute__((__unused__))
#endif
#ifndef HIDDEN
#define HIDDEN __attribute__((__visibility__ ("hidden")))
#endif
#ifndef PUBLIC
#define PUBLIC __attribute__((__visibility__ ("default")))
#endif
#ifndef DEPRECATED
#define DEPRECATED __attribute__((__deprecated__))
#endif
#ifndef DESTRUCTOR
#define DESTRUCTOR __attribute__((destructor))
#endif
#ifndef CONSTRUCTOR
#define CONSTRUCTOR __attribute__((constructor))
#endif
#ifndef ALIAS
#define ALIAS(x) __attribute__((weak, alias (#x)))
#endif
#ifndef ALLOCFUNC
#if defined(__COVERITY__)
#define ALLOCFUNC(a, b)
#else
#define ALLOCFUNC(dealloc, dealloc_arg) __attribute__((__malloc__(dealloc, dealloc_arg)))
#endif
#endif
#ifndef PRINTF
#define PRINTF(first, args...) __attribute__((__format__(printf, first, ## args)))
#endif
#ifndef PURE
#define PURE __attribute__((__pure__))
#endif
#ifndef FLATTEN
#define FLATTEN __attribute__((__flatten__))
#endif
#ifndef PACKED
#define PACKED __attribute__((__packed__))
#endif
#ifndef NORETURN
#define NORETURN __attribute__((__noreturn__))
#endif
#ifndef ALIGNED
#define ALIGNED(n) __attribute__((__aligned__(n)))
#endif
#ifndef CLEANUP_FUNC
#define CLEANUP_FUNC(x) __attribute__((__cleanup__(x)))
#endif
#ifndef USED
#define USED __attribute__((__used__))
#endif
#ifndef SECTION
#define SECTION(x) __attribute__((__section__(x)))
#endif
#ifndef OPTIMIZE
#define OPTIMIZE(x) __attribute__((__optimize__(x)))
#endif

#ifndef __CONCAT
#define __CONCAT(a, b) a ## b
#endif
#ifndef __CONCAT3
#define __CONCAT3(a, b, c) a ## b ## c
#endif
#ifndef CAT
#define CAT(a, b) __CONCAT(a, b)
#endif
#ifndef CAT3
#define CAT3(a, b, c) __CONCAT3(a, b, c)
#endif
#ifndef STRING
#define STRING(x) __STRING(x)
#endif
#ifndef as_lstring
#define as_lstring(x) __CONCAT(L, x)
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(var, val) \
        (*((volatile typeof(val) *)(&(var))) = (val))
#endif

#ifndef READ_ONCE
#define READ_ONCE(var) (*((volatile typeof(var) *)(&(var))))
#endif

#ifndef likely
#define likely(x)	__builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x)	__builtin_expect(!!(x), 0)
#endif

/* Are two types/vars the same type (ignoring qualifiers)? */
#ifndef __same_type
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#endif

/* Compile time object size, -1 for unknown */
#ifndef __compiletime_object_size
# define __compiletime_object_size(obj) -1
#endif
#ifndef __compiletime_warning
# define __compiletime_warning(message)
#endif
#ifndef __compiletime_error
# define __compiletime_error(message)
#endif

#ifndef __compiletime_assert
#define __compiletime_assert(condition, msg, prefix, suffix)		\
	do {								\
		extern void prefix ## suffix(void) __compiletime_error(msg); \
		if (!(condition))					\
			prefix ## suffix();				\
	} while (0)
#endif

#ifndef _compiletime_assert
#define _compiletime_assert(condition, msg, prefix, suffix) \
	__compiletime_assert(condition, msg, prefix, suffix)
#endif

/**
 * compiletime_assert - break build and emit msg if condition is false
 * @condition: a compile-time constant condition to check
 * @msg:       a message to emit if condition is false
 *
 * In tradition of POSIX assert, this macro will break the build if the
 * supplied condition is *false*, emitting the supplied error message if the
 * compiler has support to do so.
 */
#ifndef compiletime_assert
#define compiletime_assert(condition, msg) \
	_compiletime_assert(condition, msg, __compiletime_assert_, __LINE__ - 1)
#endif

/**
 * BUILD_BUG_ON_MSG - break compile if a condition is true & emit supplied
 *		      error message.
 * @condition: the condition which the compiler should know is false.
 *
 * See BUILD_BUG_ON for description.
 */
#ifndef BUILD_BUG_ON_MSG
#define BUILD_BUG_ON_MSG(cond, msg) compiletime_assert(!(cond), msg)
#endif

#ifndef ALIGN
#define __ALIGN_MASK(x, mask)   (((x) + (mask)) & ~(mask))
#define __ALIGN(x, a)           __ALIGN_MASK(x, (typeof(x))(a) - 1)
#define ALIGN(x, a)             __ALIGN((x), (a))
#endif
#ifndef ALIGN_DOWN
#define ALIGN_DOWN(x, a)        __ALIGN((x) - ((a) - 1), (a))
#endif

#define MIN(a, b) ({(a) < (b) ? (a) : (b);})
#define MAX(a, b) ({(a) <= (b) ? (b) : (a);})

/**
 * Builtins that don't go in string.h
 */
#define unreachable() __builtin_unreachable()

#endif /* !COMPILER_H_ */
// vim:fenc=utf-8:tw=75:et
