// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Stripped-down version of Bitcoin Core's streams.h.

#ifndef BITCOIN_STREAMS_H
#define BITCOIN_STREAMS_H

#include <serialize.h>
#include <span.h>

#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ios>
#include <span>
#include <string>
#include <vector>

/** Double ended buffer combining vector and stream-like interfaces.
 *
 * >> and << read and write unformatted data using the above serialization templates.
 * Fills with data in linear time; some stringstream implementations take N^2 time.
 */
class DataStream
{
protected:
    using vector_type = std::vector<std::byte>;
    vector_type vch;
    vector_type::size_type m_read_pos{0};

public:
    typedef vector_type::allocator_type   allocator_type;
    typedef vector_type::size_type        size_type;
    typedef vector_type::difference_type  difference_type;
    typedef vector_type::reference        reference;
    typedef vector_type::const_reference  const_reference;
    typedef vector_type::value_type       value_type;
    typedef vector_type::iterator         iterator;
    typedef vector_type::const_iterator   const_iterator;
    typedef vector_type::reverse_iterator reverse_iterator;

    explicit DataStream() = default;
    explicit DataStream(std::span<const uint8_t> sp) : DataStream{std::as_bytes(sp)} {}
    explicit DataStream(std::span<const value_type> sp) : vch(sp.data(), sp.data() + sp.size()) {}

    std::string str() const
    {
        return std::string{UCharCast(data()), UCharCast(data() + size())};
    }

    //
    // Vector subset
    //
    const_iterator begin() const                     { return vch.begin() + m_read_pos; }
    iterator begin()                                 { return vch.begin() + m_read_pos; }
    const_iterator end() const                       { return vch.end(); }
    iterator end()                                   { return vch.end(); }
    size_type size() const                           { return vch.size() - m_read_pos; }
    bool empty() const                               { return vch.size() == m_read_pos; }
    void resize(size_type n, value_type c = value_type{}) { vch.resize(n + m_read_pos, c); }
    void reserve(size_type n)                        { vch.reserve(n + m_read_pos); }
    const_reference operator[](size_type pos) const  { return vch[pos + m_read_pos]; }
    reference operator[](size_type pos)              { return vch[pos + m_read_pos]; }
    void clear()                                     { vch.clear(); m_read_pos = 0; }
    value_type* data()                               { return vch.data() + m_read_pos; }
    const value_type* data() const                   { return vch.data() + m_read_pos; }

    //
    // Stream subset
    //
    void read(std::span<value_type> dst)
    {
        if (dst.size() == 0) return;

        // Read from the beginning of the buffer
        if (dst.size() > size()) {
            throw std::ios_base::failure("DataStream::read(): end of data");
        }
        memcpy(dst.data(), &vch[m_read_pos], dst.size());
        if (dst.size() == size()) {
            // If fully consumed, reset to empty state.
            clear();
            return;
        }
        m_read_pos += dst.size();
    }

    void ignore(size_t num_ignore)
    {
        // Ignore from the beginning of the buffer
        if (num_ignore > size()) {
            throw std::ios_base::failure("DataStream::ignore(): end of data");
        }
        if (num_ignore == size()) {
            // If all bytes are ignored, reset to empty state.
            clear();
            return;
        }
        m_read_pos += num_ignore;
    }

    void write(std::span<const value_type> src)
    {
        // Write to the end of the buffer
        vch.insert(vch.end(), src.begin(), src.end());
    }

    template<typename T>
    DataStream& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return (*this);
    }

    template <typename T>
    DataStream& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return (*this);
    }
};

/** Non-refcounted RAII wrapper for FILE*
 *
 * Will automatically close the file when it goes out of scope if not null.
 * If you're returning the file pointer, return file.release().
 * If you need to close the file early, use file.fclose() instead of fclose(file).
 */
class AutoFile
{
protected:
    std::FILE* m_file;

public:
    explicit AutoFile(std::FILE* file) : m_file{file} {}

    ~AutoFile() { fclose(); }

    // Disallow copies
    AutoFile(const AutoFile&) = delete;
    AutoFile& operator=(const AutoFile&) = delete;

    bool feof() const { return std::feof(m_file); }

    int fclose()
    {
        if (auto rel{release()}) return std::fclose(rel);
        return 0;
    }

    /** Get wrapped FILE* with transfer of ownership.
     * @note This will invalidate the AutoFile object, and makes it the responsibility of the caller
     * of this function to clean up the returned FILE*.
     */
    std::FILE* release()
    {
        std::FILE* ret{m_file};
        m_file = nullptr;
        return ret;
    }

    /** Return true if the wrapped FILE* is nullptr, false otherwise.
     */
    bool IsNull() const { return m_file == nullptr; }

    //
    // Stream subset
    //
    void read(std::span<std::byte> dst)
    {
        if (!m_file) throw std::ios_base::failure("AutoFile::read: file handle is nullptr");
        if (std::fread(dst.data(), 1, dst.size(), m_file) != dst.size()) {
            throw std::ios_base::failure(feof() ? "AutoFile::read: end of file" : "AutoFile::read: fread failed");
        }
    }

    void ignore(size_t nSize)
    {
        if (!m_file) throw std::ios_base::failure("AutoFile::ignore: file handle is nullptr");
        unsigned char data[4096];
        while (nSize > 0) {
            size_t nNow = std::min<size_t>(nSize, sizeof(data));
            if (std::fread(data, 1, nNow, m_file) != nNow) {
                throw std::ios_base::failure(feof() ? "AutoFile::ignore: end of file" : "AutoFile::ignore: fread failed");
            }
            nSize -= nNow;
        }
    }

    void write(std::span<const std::byte> src)
    {
        if (!m_file) throw std::ios_base::failure("AutoFile::write: file handle is nullptr");
        if (std::fwrite(src.data(), 1, src.size(), m_file) != src.size()) {
            throw std::ios_base::failure("AutoFile::write: write failed");
        }
    }

    template <typename T>
    AutoFile& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

    template <typename T>
    AutoFile& operator>>(T&& obj)
    {
        ::Unserialize(*this, obj);
        return *this;
    }
};

#endif // BITCOIN_STREAMS_H
