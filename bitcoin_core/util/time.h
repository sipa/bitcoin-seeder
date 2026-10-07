// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's util/time.h, with only the clock
// and time point types and conversion helpers (and without mock time).

#ifndef BITCOIN_UTIL_TIME_H
#define BITCOIN_UTIL_TIME_H

#include <chrono> // IWYU pragma: export

using namespace std::chrono_literals;

using SteadyClock = std::chrono::steady_clock;

/** The clock for timestamps (which, unlike SteadyClock, is relative to the Unix epoch). */
using NodeClock = std::chrono::system_clock;
using NodeSeconds = std::chrono::time_point<NodeClock, std::chrono::seconds>;

/**
 * Helper to count the seconds of a duration/time_point.
 *
 * All durations/time_points should be using std::chrono and calling this should generally
 * be avoided in code. Though, it is still preferred to an inline t.count() to
 * protect against a reliance on the exact type of t.
 *
 * This helper is used to convert durations/time_points before passing them over an
 * interface that doesn't support std::chrono (e.g. printf)
 */
template <typename Dur1, typename Dur2>
constexpr auto Ticks(Dur2 d)
{
    return std::chrono::duration_cast<Dur1>(d).count();
}
template <typename Duration, typename Timepoint>
constexpr auto TicksSinceEpoch(Timepoint t)
{
    return Ticks<Duration>(t.time_since_epoch());
}

/**
 * Return the current time point cast to the given precision. Only use this
 * when an exact precision is needed, otherwise use T::clock::now() directly.
 */
template <typename T>
T Now()
{
    return std::chrono::time_point_cast<typename T::duration>(T::clock::now());
}

#endif // BITCOIN_UTIL_TIME_H
