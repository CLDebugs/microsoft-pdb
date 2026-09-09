#include <algorithm>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>
#include <windows.h>

namespace {

using Byte = std::uint8_t;
using Bytes = std::vector<Byte>;

constexpr char kMsfMagic[] = "Microsoft C/C++ MSF 7.00\r\n\x1a" "DS";
constexpr std::uint32_t kNilSize = 0xffffffffu;
constexpr std::uint32_t kPdbStream = 1;
constexpr std::uint32_t kDbiStream = 3;
constexpr std::size_t kDbiHeaderSize = 64;
constexpr std::size_t kModiFixedSize = 64;

constexpr std::uint32_t kLines = 0xf2;
constexpr std::uint32_t kStringTable = 0xf3;
constexpr std::uint32_t kFileChecksums = 0xf4;
constexpr std::uint32_t kInlineeLines = 0xf6;
constexpr std::uint32_t kIlLines = 0xf9;
constexpr std::uint16_t kObjName = 0x1101;
constexpr std::uint16_t kEnvBlock = 0x113d;
constexpr std::uint16_t kInlineSite = 0x114d;
constexpr std::uint16_t kFileStatic = 0x1153;
constexpr std::uint16_t kInlineSite2 = 0x115d;
constexpr std::uint16_t kLfBuildInfo = 0x1603;
constexpr std::uint16_t kLfSubstrList = 0x1604;
constexpr std::uint16_t kLfStringId = 0x1605;
constexpr std::uint16_t kLfUdtSrcLine = 0x1606;
constexpr std::uint16_t kLfUdtModSrcLine = 0x1607;

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class TemporaryFile {
public:
    explicit TemporaryFile(const std::filesystem::path& output) {
        const auto directory =
            output.has_parent_path() ? output.parent_path() : std::filesystem::current_path();
        const auto stem = output.filename().wstring();
        for (std::uint32_t attempt = 0; attempt != 1000; ++attempt) {
            path_ = directory / (stem + L"." + std::to_wstring(GetCurrentProcessId()) + L"." +
                                 std::to_wstring(GetTickCount64()) + L"." +
                                 std::to_wstring(attempt) + L".tmp");
            HANDLE file = CreateFileW(path_.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                      CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                CloseHandle(file);
                return;
            }
            const DWORD error = GetLastError();
            if (error != ERROR_FILE_EXISTS && error != ERROR_ALREADY_EXISTS)
                throw Error("cannot create temporary output");
        }
        throw Error("cannot allocate a unique temporary output");
    }

    ~TemporaryFile() {
        if (owned_) {
            std::error_code error;
            std::filesystem::remove(path_, error);
        }
    }

    const std::filesystem::path& path() const { return path_; }
    void release() { owned_ = false; }

private:
    std::filesystem::path path_;
    bool owned_ = true;
};

std::uint16_t read16(const Bytes& data, std::size_t offset) {
    if (offset + 2 > data.size()) throw Error("truncated 16-bit value");
    return static_cast<std::uint16_t>(data[offset] | data[offset + 1] << 8);
}

std::uint32_t read32(const Bytes& data, std::size_t offset) {
    if (offset + 4 > data.size()) throw Error("truncated 32-bit value");
    return static_cast<std::uint32_t>(data[offset]) |
           static_cast<std::uint32_t>(data[offset + 1]) << 8 |
           static_cast<std::uint32_t>(data[offset + 2]) << 16 |
           static_cast<std::uint32_t>(data[offset + 3]) << 24;
}

void write16(Bytes& data, std::size_t offset, std::uint16_t value) {
    if (offset + 2 > data.size()) throw Error("16-bit write is out of bounds");
    data[offset] = static_cast<Byte>(value);
    data[offset + 1] = static_cast<Byte>(value >> 8);
}

void write32(Bytes& data, std::size_t offset, std::uint32_t value) {
    if (offset + 4 > data.size()) throw Error("32-bit write is out of bounds");
    for (unsigned i = 0; i != 4; ++i) data[offset + i] = static_cast<Byte>(value >> (i * 8));
}

void append32(Bytes& data, std::uint32_t value) {
    const auto old = data.size();
    data.resize(old + 4);
    write32(data, old, value);
}

std::size_t align4(std::size_t value) { return (value + 3) & ~std::size_t(3); }

std::size_t cstringEnd(const Bytes& data, std::size_t offset, std::size_t limit) {
    if (offset >= limit || limit > data.size()) throw Error("missing string");
    while (offset < limit && data[offset] != 0) ++offset;
    if (offset == limit) throw Error("unterminated string");
    return offset + 1;
}

void redactDirectory(Bytes& data, std::size_t start, std::size_t end) {
    if (end <= start) return;
    auto separator = end;
    if (data[separator - 1] == 0) --separator;
    while (separator != start && data[separator - 1] != '\\' && data[separator - 1] != '/')
        --separator;
    if (separator == start) return;
    std::fill(data.begin() + start, data.begin() + separator, Byte{'_'});
}

struct Stream {
    std::uint32_t size = kNilSize;
    std::vector<std::uint32_t> blocks;
};

class Msf {
public:
    explicit Msf(const std::filesystem::path& path)
        : file_(path, std::ios::binary | std::ios::in | std::ios::out) {
        if (!file_) throw Error("cannot open output PDB");
        Bytes header = readAt(0, 56);
        if (std::memcmp(header.data(), kMsfMagic, sizeof(kMsfMagic) - 1) != 0)
            throw Error("only MSF 7.00 PDB files are supported");
        pageSize_ = read32(header, 32);
        pageCount_ = read32(header, 40);
        directorySize_ = read32(header, 44);
        unknown_ = read32(header, 48);
        blockMap_ = read32(header, 52);
        magic_.assign(header.begin(), header.begin() + 32);
        if (pageSize_ != 512 && pageSize_ != 1024 && pageSize_ != 2048 && pageSize_ != 4096)
            throw Error("unsupported MSF page size");

        const auto directoryPages = pagesFor(directorySize_);
        if (directoryPages * 4 > pageSize_) throw Error("large MSF directory block maps are unsupported");
        Bytes map = readPage(blockMap_);
        for (std::size_t i = 0; i != directoryPages; ++i)
            directoryBlocks_.push_back(read32(map, i * 4));
        Bytes directory = readBlocks(directoryBlocks_, directorySize_);
        parseDirectory(directory);
    }

    Bytes readStream(std::uint32_t number) {
        if (number >= streams_.size() || streams_[number].size == kNilSize)
            throw Error("referenced stream is absent");
        return readBlocks(streams_[number].blocks, streams_[number].size);
    }

    void writeStream(std::uint32_t number, const Bytes& data) {
        if (number >= streams_.size() || streams_[number].size == kNilSize)
            throw Error("referenced stream is absent");
        auto& stream = streams_[number];
        const auto required = pagesFor(data.size());
        if (required > stream.blocks.size()) throw Error("rewritten stream grew unexpectedly");
        for (std::size_t i = 0, cursor = 0; i != stream.blocks.size(); ++i) {
            Bytes page(pageSize_);
            if (i < required) {
                const auto count = std::min<std::size_t>(pageSize_, data.size() - cursor);
                std::copy_n(data.begin() + cursor, count, page.begin());
                cursor += count;
            }
            writeAt(static_cast<std::uint64_t>(stream.blocks[i]) * pageSize_, page);
        }
        stream.size = static_cast<std::uint32_t>(data.size());
        stream.blocks.resize(required);
    }

    void clearStream(std::uint32_t number) {
        Bytes data = readStream(number);
        std::fill(data.begin(), data.end(), Byte{0});
        writeStream(number, data);
    }

    void writeCompact(const std::filesystem::path& path) {
        struct CompactStream {
            std::uint32_t size;
            Bytes data;
            std::vector<std::uint32_t> blocks;
        };
        std::vector<CompactStream> compact;
        compact.reserve(streams_.size());
        for (std::uint32_t number = 0; number != streams_.size(); ++number) {
            if (number == 0)
                compact.push_back({0, {}, {}});
            else if (streams_[number].size == kNilSize)
                compact.push_back({kNilSize, {}, {}});
            else
                compact.push_back({streams_[number].size, readStream(number), {}});
        }

        std::uint32_t nextBlock = 3;
        auto allocateBlock = [&]() {
            while (nextBlock % pageSize_ == 1 || nextBlock % pageSize_ == 2)
                ++nextBlock;
            return nextBlock++;
        };

        for (auto& stream : compact)
            for (std::size_t i = 0; i != pagesFor(stream.data.size()); ++i)
                stream.blocks.push_back(allocateBlock());

        Bytes directory;
        append32(directory, static_cast<std::uint32_t>(compact.size()));
        for (const auto& stream : compact) append32(directory, stream.size);
        for (const auto& stream : compact)
            for (auto block : stream.blocks) append32(directory, block);

        std::vector<std::uint32_t> directoryBlocks;
        for (std::size_t i = 0; i != pagesFor(directory.size()); ++i)
            directoryBlocks.push_back(allocateBlock());
        if (directoryBlocks.size() * 4 > pageSize_)
            throw Error("compact MSF requires a multi-page block map");
        const auto blockMap = allocateBlock();
        const auto blockCount = nextBlock;

        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) throw Error("cannot create compact output PDB");
        output.seekp(static_cast<std::streamoff>(
            static_cast<std::uint64_t>(blockCount) * pageSize_ - 1));
        output.put('\0');
        if (!output) throw Error("cannot size compact output PDB");

        auto writePage = [&](std::uint32_t block, const Byte* data, std::size_t size) {
            Bytes page(pageSize_);
            if (size) std::copy_n(data, size, page.begin());
            output.seekp(static_cast<std::streamoff>(
                static_cast<std::uint64_t>(block) * pageSize_));
            output.write(reinterpret_cast<const char*>(page.data()), page.size());
            if (!output) throw Error("failed writing compact output PDB");
        };

        Bytes header(pageSize_);
        std::copy(magic_.begin(), magic_.end(), header.begin());
        write32(header, 32, pageSize_);
        write32(header, 36, 1);
        write32(header, 40, blockCount);
        write32(header, 44, static_cast<std::uint32_t>(directory.size()));
        write32(header, 48, unknown_);
        write32(header, 52, blockMap);
        writePage(0, header.data(), header.size());

        for (const auto& stream : compact) {
            for (std::size_t i = 0; i != stream.blocks.size(); ++i) {
                const auto offset = i * pageSize_;
                const auto count = std::min<std::size_t>(
                    pageSize_, stream.data.size() - offset);
                writePage(stream.blocks[i], stream.data.data() + offset, count);
            }
        }
        for (std::size_t i = 0; i != directoryBlocks.size(); ++i) {
            const auto offset = i * pageSize_;
            const auto count = std::min<std::size_t>(
                pageSize_, directory.size() - offset);
            writePage(directoryBlocks[i], directory.data() + offset, count);
        }
        Bytes blockMapData(pageSize_);
        for (std::size_t i = 0; i != directoryBlocks.size(); ++i)
            write32(blockMapData, i * 4, directoryBlocks[i]);
        writePage(blockMap, blockMapData.data(), blockMapData.size());

        const auto fpmCoverage = static_cast<std::uint64_t>(pageSize_) * 8;
        const auto fpmChunks = (blockCount + fpmCoverage - 1) / fpmCoverage;
        for (std::uint32_t chunk = 0; chunk != fpmChunks; ++chunk) {
            Bytes fpm(pageSize_, Byte{0xff});
            const auto firstBlock = static_cast<std::uint64_t>(chunk) * fpmCoverage;
            const auto used = std::min<std::uint64_t>(
                fpmCoverage, blockCount - firstBlock);
            for (std::uint64_t bit = 0; bit != used; ++bit)
                fpm[bit / 8] &= static_cast<Byte>(~(1u << (bit % 8)));
            writePage(1 + chunk * pageSize_, fpm.data(), fpm.size());
            writePage(2 + chunk * pageSize_, fpm.data(), fpm.size());
        }
        output.flush();
        if (!output) throw Error("failed finalizing compact output PDB");
    }

    void commitDirectory() {
        Bytes directory;
        append32(directory, static_cast<std::uint32_t>(streams_.size()));
        for (const auto& stream : streams_) append32(directory, stream.size);
        for (const auto& stream : streams_)
            for (auto block : stream.blocks) append32(directory, block);
        if (directory.size() > directoryBlocks_.size() * pageSize_)
            throw Error("rewritten stream directory grew unexpectedly");
        for (std::size_t i = 0, cursor = 0; i != directoryBlocks_.size(); ++i) {
            Bytes page(pageSize_);
            const auto count = cursor < directory.size()
                ? std::min<std::size_t>(pageSize_, directory.size() - cursor)
                : 0;
            if (count) std::copy_n(directory.begin() + cursor, count, page.begin());
            cursor += count;
            writeAt(static_cast<std::uint64_t>(directoryBlocks_[i]) * pageSize_, page);
        }
        Bytes sizeBytes(4);
        write32(sizeBytes, 0, static_cast<std::uint32_t>(directory.size()));
        writeAt(44, sizeBytes);
        file_.flush();
    }

private:
    std::fstream file_;
    std::uint32_t pageSize_ = 0;
    std::uint32_t pageCount_ = 0;
    std::uint32_t directorySize_ = 0;
    std::uint32_t unknown_ = 0;
    std::uint32_t blockMap_ = 0;
    Bytes magic_;
    std::vector<std::uint32_t> directoryBlocks_;
    std::vector<Stream> streams_;

    std::size_t pagesFor(std::size_t size) const { return (size + pageSize_ - 1) / pageSize_; }

    Bytes readAt(std::uint64_t offset, std::size_t size) {
        Bytes data(size);
        file_.seekg(static_cast<std::streamoff>(offset));
        file_.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(size));
        if (file_.gcount() != static_cast<std::streamsize>(size)) throw Error("unexpected end of PDB");
        return data;
    }

    void writeAt(std::uint64_t offset, const Bytes& data) {
        file_.seekp(static_cast<std::streamoff>(offset));
        file_.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        if (!file_) throw Error("failed writing output PDB");
    }

    Bytes readPage(std::uint32_t block) {
        if (block >= pageCount_) throw Error("invalid MSF block number");
        return readAt(static_cast<std::uint64_t>(block) * pageSize_, pageSize_);
    }

    Bytes readBlocks(const std::vector<std::uint32_t>& blocks, std::size_t size) {
        Bytes result;
        result.reserve(blocks.size() * pageSize_);
        for (auto block : blocks) {
            Bytes page = readPage(block);
            result.insert(result.end(), page.begin(), page.end());
        }
        if (result.size() < size) throw Error("stream block list is too short");
        result.resize(size);
        return result;
    }

    void parseDirectory(const Bytes& directory) {
        const auto count = read32(directory, 0);
        std::size_t cursor = 4;
        std::vector<std::uint32_t> sizes;
        sizes.reserve(count);
        for (std::uint32_t i = 0; i != count; ++i, cursor += 4) sizes.push_back(read32(directory, cursor));
        for (auto size : sizes) {
            Stream stream;
            stream.size = size;
            const auto countBlocks = size == kNilSize ? 0 : pagesFor(size);
            for (std::size_t i = 0; i != countBlocks; ++i, cursor += 4)
                stream.blocks.push_back(read32(directory, cursor));
            streams_.push_back(std::move(stream));
        }
    }
};

bool sourceSubsection(std::uint32_t type) {
    type &= ~0x80000000u;
    return type == kLines || type == kFileChecksums || type == kInlineeLines || type == kIlLines;
}

Bytes filterC13(const Bytes& input, std::set<std::uint32_t>& sourceNames) {
    for (std::size_t cursor = 0; cursor < input.size();) {
        if (cursor + 8 > input.size()) throw Error("truncated C13 subsection");
        const auto type = read32(input, cursor) & ~0x80000000u;
        const auto length = read32(input, cursor + 4);
        const auto payload = cursor + 8;
        const auto end = align4(payload + length);
        if (end > input.size()) throw Error("invalid C13 subsection length");
        if (type == kFileChecksums) {
            for (std::size_t record = payload; record < payload + length;) {
                if (record + 6 > payload + length) throw Error("truncated file checksum record");
                sourceNames.insert(read32(input, record));
                record = align4(record + 6 + input[record + 4]);
            }
        }
        cursor = end;
    }

    Bytes output;
    for (std::size_t cursor = 0; cursor < input.size();) {
        if (cursor + 8 > input.size()) throw Error("truncated C13 subsection");
        const auto type = read32(input, cursor) & ~0x80000000u;
        const auto length = read32(input, cursor + 4);
        const auto payload = cursor + 8;
        const auto end = align4(payload + length);
        if (end > input.size()) throw Error("invalid C13 subsection length");
        if (!sourceSubsection(type)) {
            const auto outputStart = output.size();
            output.insert(output.end(), input.begin() + cursor, input.begin() + end);
            if (type == kStringTable) {
                for (auto offset : sourceNames) {
                    if (offset >= length) throw Error("source filename offset is outside C13 string table");
                    const auto stringStart = outputStart + 8 + offset;
                    const auto stringEnd = cstringEnd(output, stringStart, outputStart + 8 + length);
                    std::fill(output.begin() + stringStart, output.begin() + stringEnd - 1, Byte{'_'});
                }
            }
        } else {
            const auto outputStart = output.size();
            output.resize(outputStart + (end - cursor), Byte{0});
            write32(output, outputStart, 0x80000000u);
            write32(output, outputStart + 4, length);
        }
        cursor = end;
    }
    return output;
}

Bytes sanitizeSymbols(const Bytes& input, std::set<std::uint32_t>& sourceNames) {
    Bytes output = input;
    if (output.empty()) return output;
    if (output.size() < 4) throw Error("truncated module symbols");
    for (std::size_t cursor = 4; cursor < output.size();) {
        const auto recordSize = static_cast<std::size_t>(read16(output, cursor)) + 2;
        if (recordSize < 4 || cursor + recordSize > output.size()) throw Error("invalid CodeView symbol");
        const auto type = read16(output, cursor + 2);
        if (type == kObjName) {
            if (recordSize < 9) throw Error("truncated S_OBJNAME");
            const auto end = cstringEnd(output, cursor + 8, cursor + recordSize);
            redactDirectory(output, cursor + 8, end);
        } else if (type == kEnvBlock) {
            if (recordSize < 6) throw Error("truncated S_ENVBLOCK");
            std::size_t string = cursor + 5;
            while (string < cursor + recordSize && output[string] != 0) {
                const auto keyEnd = cstringEnd(output, string, cursor + recordSize);
                if (keyEnd >= cursor + recordSize) throw Error("truncated S_ENVBLOCK value");
                const auto valueEnd = cstringEnd(output, keyEnd, cursor + recordSize);
                std::string key(reinterpret_cast<const char*>(output.data() + string),
                                keyEnd - string - 1);
                std::transform(key.begin(), key.end(), key.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                if (key == "cwd" || key == "exe" || key == "src" ||
                    key == "pdb" || key == "cmd")
                    std::fill(output.begin() + keyEnd, output.begin() + valueEnd - 1, Byte{'_'});
                string = valueEnd;
            }
        } else if (type == kFileStatic) {
            if (recordSize < 14) throw Error("truncated S_FILESTATIC");
            sourceNames.insert(read32(output, cursor + 8));
            write32(output, cursor + 8, 0);
        } else if (type == kInlineSite) {
            if (recordSize < 16) throw Error("truncated S_INLINESITE");
            std::fill(output.begin() + cursor + 16, output.begin() + cursor + recordSize, Byte{0});
        } else if (type == kInlineSite2) {
            if (recordSize < 20) throw Error("truncated S_INLINESITE2");
            std::fill(output.begin() + cursor + 20, output.begin() + cursor + recordSize, Byte{0});
        }
        cursor += recordSize;
    }
    return output;
}

std::vector<std::size_t> moduleRecords(const Bytes& modules) {
    std::vector<std::size_t> result;
    for (std::size_t cursor = 0; cursor < modules.size();) {
        if (cursor + kModiFixedSize > modules.size()) throw Error("truncated DBI module record");
        const auto moduleEnd = cstringEnd(modules, cursor + kModiFixedSize, modules.size());
        const auto objectEnd = cstringEnd(modules, moduleEnd, modules.size());
        result.push_back(cursor);
        cursor = align4(objectEnd);
    }
    return result;
}

struct DbiResult {
    std::set<std::string> sourceNames;
    std::size_t modules = 0;
    std::size_t moduleStreams = 0;
};

DbiResult rewriteDbi(Msf& msf) {
    Bytes dbi = msf.readStream(kDbiStream);
    if (dbi.size() < kDbiHeaderSize || read32(dbi, 0) != 0xffffffffu)
        throw Error("unsupported DBI stream");
    const auto cbModules = read32(dbi, 24);
    const auto cbSc = read32(dbi, 28);
    const auto cbSecMap = read32(dbi, 32);
    const auto cbFiles = read32(dbi, 36);
    const auto cbTs = read32(dbi, 40);
    const auto cbDbg = read32(dbi, 48);
    const auto cbEc = read32(dbi, 52);
    const auto modulesEnd = kDbiHeaderSize + cbModules;
    const auto scEnd = modulesEnd + cbSc;
    const auto secMapEnd = scEnd + cbSecMap;
    const auto filesEnd = secMapEnd + cbFiles;
    const auto tsEnd = filesEnd + cbTs;
    const auto ecEnd = tsEnd + cbEc;
    const auto dbgEnd = ecEnd + cbDbg;
    if (dbgEnd > dbi.size()) throw Error("DBI substreams exceed stream size");

    Bytes modules(dbi.begin() + kDbiHeaderSize, dbi.begin() + modulesEnd);
    const auto records = moduleRecords(modules);
    DbiResult result;
    result.modules = records.size();
    for (auto offset : records) {
        const auto moduleEnd = cstringEnd(modules, offset + kModiFixedSize, modules.size());
        const auto objectEnd = cstringEnd(modules, moduleEnd, modules.size());
        redactDirectory(modules, offset + kModiFixedSize, moduleEnd);
        redactDirectory(modules, moduleEnd, objectEnd);
        const auto streamNumber = read16(modules, offset + 34);
        const auto symbolsSize = read32(modules, offset + 36);
        const auto oldLinesSize = read32(modules, offset + 40);
        const auto c13Size = read32(modules, offset + 44);
        write32(modules, offset + 40, 0);
        write16(modules, offset + 48, 0);
        write32(modules, offset + 52, 0);
        write32(modules, offset + 56, 0);
        write16(modules, offset + 32, read16(modules, offset + 32) & ~std::uint16_t(2));
        if (streamNumber == 0xffff) continue;
        ++result.moduleStreams;
        Bytes stream = msf.readStream(streamNumber);
        const auto c13Start = static_cast<std::size_t>(symbolsSize) + oldLinesSize;
        const auto c13End = c13Start + c13Size;
        if (c13End > stream.size()) throw Error("truncated module stream");
        std::set<std::uint32_t> moduleSourceNames;
        Bytes symbols(stream.begin(), stream.begin() + symbolsSize);
        symbols = sanitizeSymbols(symbols, moduleSourceNames);
        Bytes c13(stream.begin() + c13Start, stream.begin() + c13End);
        c13 = filterC13(c13, moduleSourceNames);
        write32(modules, offset + 44, static_cast<std::uint32_t>(c13.size()));
        Bytes rewritten = std::move(symbols);
        rewritten.insert(rewritten.end(), c13.begin(), c13.end());
        rewritten.insert(rewritten.end(), stream.begin() + c13End, stream.end());
        msf.writeStream(streamNumber, rewritten);
    }

    Bytes header(dbi.begin(), dbi.begin() + kDbiHeaderSize);
    Bytes fileInfo(dbi.begin() + secMapEnd, dbi.begin() + filesEnd);
    if (!fileInfo.empty()) {
        if (fileInfo.size() < 4 + records.size() * 4)
            throw Error("truncated DBI file-info substream");
        const auto moduleCount = read16(fileInfo, 0);
        if (moduleCount != records.size()) throw Error("invalid DBI file-info module count");
        const std::size_t fileCountsStart = 4 + static_cast<std::size_t>(moduleCount) * 2;
        std::size_t fileRefCount = 0;
        for (std::uint16_t module = 0; module != moduleCount; ++module) {
            const auto count = read16(fileInfo, fileCountsStart + static_cast<std::size_t>(module) * 2);
            if (fileRefCount > (std::numeric_limits<std::size_t>::max)() - count)
                throw Error("DBI file-reference count overflow");
            fileRefCount += count;
        }
        const std::size_t namesStart = fileCountsStart +
                                       static_cast<std::size_t>(moduleCount) * 2 +
                                       fileRefCount * 4;
        if (namesStart > fileInfo.size()) throw Error("invalid DBI file-info substream");
        for (std::size_t cursor = namesStart; cursor < fileInfo.size();) {
            const auto end = cstringEnd(fileInfo, cursor, fileInfo.size());
            if (end > cursor + 1)
                result.sourceNames.emplace(
                    reinterpret_cast<const char*>(fileInfo.data() + cursor),
                    end - cursor - 1);
            cursor = end;
        }
        std::fill(fileInfo.begin(), fileInfo.end(), Byte{0});
        write16(fileInfo, 0, static_cast<std::uint16_t>(records.size()));
    }
    Bytes ecInfo(dbi.begin() + tsEnd, dbi.begin() + ecEnd);
    if (!ecInfo.empty()) {
        if (ecInfo.size() < 12 || read32(ecInfo, 0) != 0xeffeeffe)
            throw Error("unsupported DBI edit-and-continue source map");
        const auto stringSize = read32(ecInfo, 8);
        if (12 + stringSize > ecInfo.size())
            throw Error("truncated DBI edit-and-continue source map");
        for (std::size_t cursor = 12; cursor < 12 + stringSize; ++cursor)
            if (ecInfo[cursor] != 0) ecInfo[cursor] = Byte{'_'};
    }
    Bytes rewritten = std::move(header);
    rewritten.insert(rewritten.end(), modules.begin(), modules.end());
    rewritten.insert(rewritten.end(), dbi.begin() + modulesEnd, dbi.begin() + secMapEnd);
    rewritten.insert(rewritten.end(), fileInfo.begin(), fileInfo.end());
    rewritten.insert(rewritten.end(), dbi.begin() + filesEnd, dbi.begin() + tsEnd);
    rewritten.insert(rewritten.end(), ecInfo.begin(), ecInfo.end());
    rewritten.insert(rewritten.end(), dbi.begin() + ecEnd, dbi.end());
    msf.writeStream(kDbiStream, rewritten);
    return result;
}

struct TypeRecord {
    std::size_t offset;
    std::size_t size;
    std::uint16_t leaf;
};

std::uint32_t pdbCrc32(const Byte* bytes, std::size_t size) {
    std::uint32_t crc = 0;
    while (size-- != 0) {
        crc ^= *bytes++;
        for (unsigned bit = 0; bit != 8; ++bit)
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return crc;
}

struct IpiResult {
    std::size_t buildInfoRecords = 0;
    std::size_t udtSourceLineRecords = 0;
    std::size_t stringIdsRedacted = 0;
};

IpiResult sanitizeIpi(Msf& msf) {
    constexpr std::uint32_t ipiStream = 4;
    Bytes ipi = msf.readStream(ipiStream);
    IpiResult result;
    if (ipi.empty()) return result;
    if (ipi.size() < 20) throw Error("truncated IPI stream");
    const auto headerSize = read32(ipi, 4);
    const auto idMin = read32(ipi, 8);
    const auto idMax = read32(ipi, 12);
    const auto recordBytes = read32(ipi, 16);
    if (headerSize > ipi.size() || headerSize + recordBytes > ipi.size())
        throw Error("invalid IPI stream header");

    std::map<std::uint32_t, TypeRecord> records;
    std::size_t cursor = headerSize;
    for (std::uint32_t id = idMin; id != idMax; ++id) {
        if (cursor + 4 > headerSize + recordBytes) throw Error("truncated IPI record");
        const auto size = static_cast<std::size_t>(read16(ipi, cursor)) + 2;
        if (size < 4 || cursor + size > headerSize + recordBytes)
            throw Error("invalid IPI record length");
        records.emplace(id, TypeRecord{cursor, size, read16(ipi, cursor + 2)});
        cursor += size;
    }
    if (cursor != headerSize + recordBytes) throw Error("IPI record count does not match header");

    std::set<std::uint32_t> redactIds;
    for (const auto& [id, record] : records) {
        (void)id;
        if (record.leaf == kLfBuildInfo) {
            ++result.buildInfoRecords;
            if (record.size < 6) throw Error("truncated LF_BUILDINFO");
            const auto count = read16(ipi, record.offset + 4);
            if (6 + static_cast<std::size_t>(count) * 4 > record.size)
                throw Error("invalid LF_BUILDINFO");
            for (std::uint16_t argument = 0; argument != count; ++argument)
                redactIds.insert(read32(ipi, record.offset + 6 + argument * 4));
        } else if (record.leaf == kLfUdtSrcLine || record.leaf == kLfUdtModSrcLine) {
            ++result.udtSourceLineRecords;
            if (record.size < 16) throw Error("truncated UDT source-line record");
            redactIds.insert(read32(ipi, record.offset + 8));
            write32(ipi, record.offset + 12, 0);
        }
    }

    std::set<std::uint32_t> visited;
    std::set<std::uint32_t> modifiedStringIds;
    while (!redactIds.empty()) {
        const auto id = *redactIds.begin();
        redactIds.erase(redactIds.begin());
        if (id < idMin || id >= idMax || !visited.insert(id).second) continue;
        const auto record = records.at(id);
        if (record.leaf == kLfStringId) {
            modifiedStringIds.insert(id);
            if (record.size < 9) throw Error("truncated LF_STRING_ID");
            redactIds.insert(read32(ipi, record.offset + 4));
            const auto stringStart = record.offset + 8;
            const auto stringEnd = cstringEnd(ipi, stringStart, record.offset + record.size);
            std::fill(ipi.begin() + stringStart, ipi.begin() + stringEnd - 1, Byte{'_'});
        } else if (record.leaf == kLfSubstrList) {
            if (record.size < 8) throw Error("truncated LF_SUBSTR_LIST");
            const auto count = read32(ipi, record.offset + 4);
            if (8 + static_cast<std::size_t>(count) * 4 > record.size)
                throw Error("invalid LF_SUBSTR_LIST");
            for (std::uint32_t i = 0; i != count; ++i)
                redactIds.insert(read32(ipi, record.offset + 8 + i * 4));
        }
    }

    const auto hashStreamNumber = read16(ipi, 20);
    const auto hashKeySize = read32(ipi, 24);
    const auto hashBuckets = read32(ipi, 28);
    const auto hashOffset = read32(ipi, 32);
    const auto hashSize = read32(ipi, 36);
    if (!modifiedStringIds.empty()) {
        if (hashStreamNumber == 0xffff || hashKeySize != 4 || hashBuckets == 0)
            throw Error("unsupported IPI hash metadata");
        Bytes hashes = msf.readStream(hashStreamNumber);
        const auto requiredHashBytes = static_cast<std::size_t>(idMax - idMin) * hashKeySize;
        if (hashOffset > hashes.size() || hashSize < requiredHashBytes ||
            static_cast<std::size_t>(hashOffset) + requiredHashBytes > hashes.size())
            throw Error("truncated IPI hash values");
        for (auto id : modifiedStringIds) {
            const auto record = records.at(id);
            const auto hash = pdbCrc32(ipi.data() + record.offset + 2, record.size - 2) %
                              hashBuckets;
            write32(hashes, hashOffset + static_cast<std::size_t>(id - idMin) * hashKeySize,
                    hash);
        }
        msf.writeStream(hashStreamNumber, hashes);
    }
    result.stringIdsRedacted = modifiedStringIds.size();
    msf.writeStream(ipiStream, ipi);
    return result;
}

std::uint32_t nameHashV1(const Byte* bytes, std::size_t size) {
    std::uint32_t hash = 0;
    while (size >= 4) {
        hash ^= static_cast<std::uint32_t>(bytes[0]) |
                static_cast<std::uint32_t>(bytes[1]) << 8 |
                static_cast<std::uint32_t>(bytes[2]) << 16 |
                static_cast<std::uint32_t>(bytes[3]) << 24;
        bytes += 4;
        size -= 4;
    }
    if (size >= 2) {
        hash ^= static_cast<std::uint32_t>(bytes[0]) |
                static_cast<std::uint32_t>(bytes[1]) << 8;
        bytes += 2;
        size -= 2;
    }
    if (size != 0) hash ^= *bytes;
    hash |= 0x20202020u;
    hash ^= hash >> 11;
    return hash ^ (hash >> 16);
}

std::uint32_t nameHashV2(const Byte* bytes, std::size_t size) {
    std::uint32_t hash = 0xb170a1bfu;
    while (size >= 4) {
        hash += static_cast<std::uint32_t>(bytes[0]) |
                static_cast<std::uint32_t>(bytes[1]) << 8 |
                static_cast<std::uint32_t>(bytes[2]) << 16 |
                static_cast<std::uint32_t>(bytes[3]) << 24;
        hash += hash << 10;
        hash ^= hash >> 6;
        bytes += 4;
        size -= 4;
    }
    while (size-- != 0) {
        hash += *bytes++;
        hash += hash << 10;
        hash ^= hash >> 6;
    }
    return hash * 1664525u + 1013904223u;
}

std::string redactedName(std::size_t size, std::uint32_t ordinal) {
    static constexpr char alphabet[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    std::string value(size, '_');
    for (std::size_t i = 0; i != size && ordinal != 0; ++i) {
        value[size - i - 1] = alphabet[ordinal % (sizeof(alphabet) - 1)];
        ordinal /= sizeof(alphabet) - 1;
    }
    return value;
}

std::size_t redactGlobalNames(Msf& msf, std::uint32_t streamNumber,
                              const std::set<std::string>& sourceNames) {
    if (streamNumber == kNilSize || sourceNames.empty()) return 0;
    Bytes names = msf.readStream(streamNumber);
    if (names.size() < 16 || read32(names, 0) != 0xeffeeffe)
        throw Error("unsupported /names stream");
    const auto version = read32(names, 4);
    if (version != 1 && version != 2) throw Error("unsupported /names hash version");
    const auto stringSize = read32(names, 8);
    const std::size_t stringsStart = 12;
    const std::size_t stringsEnd = stringsStart + stringSize;
    if (stringsEnd + 8 > names.size()) throw Error("truncated /names stream");
    const auto hashCount = read32(names, stringsEnd);
    if (hashCount == 0) throw Error("invalid /names hash table");
    const std::size_t hashesStart = stringsEnd + 4;
    if (hashesStart + static_cast<std::size_t>(hashCount) * 4 + 4 > names.size())
        throw Error("truncated /names hash table");

    std::vector<std::uint32_t> nameOffsets;
    std::uint32_t ordinal = 1;
    std::size_t redacted = 0;
    for (std::size_t cursor = stringsStart; cursor < stringsEnd;) {
        const auto end = cstringEnd(names, cursor, stringsEnd);
        const auto length = end - cursor - 1;
        if (length != 0) {
            const std::uint32_t offset = static_cast<std::uint32_t>(cursor - stringsStart);
            nameOffsets.push_back(offset);
            std::string name(reinterpret_cast<const char*>(names.data() + cursor), length);
            if (sourceNames.count(name) != 0) {
                const auto replacement = redactedName(length, ordinal++);
                std::copy(replacement.begin(), replacement.end(), names.begin() + cursor);
                ++redacted;
            }
        }
        cursor = end;
    }

    std::vector<std::uint32_t> hashes(hashCount, 0);
    for (auto offset : nameOffsets) {
        const auto start = stringsStart + offset;
        const auto end = cstringEnd(names, start, stringsEnd);
        const auto length = end - start - 1;
        const auto hash = version == 2 ? nameHashV2(names.data() + start, length)
                                       : nameHashV1(names.data() + start, length);
        auto slot = hash % hashCount;
        while (hashes[slot] != 0) slot = (slot + 1) % hashCount;
        hashes[slot] = offset;
    }
    for (std::uint32_t slot = 0; slot != hashCount; ++slot)
        write32(names, hashesStart + static_cast<std::size_t>(slot) * 4, hashes[slot]);
    write32(names, hashesStart + static_cast<std::size_t>(hashCount) * 4,
            static_cast<std::uint32_t>(nameOffsets.size()));
    msf.writeStream(streamNumber, names);
    return redacted;
}

bool sourceStreamName(std::string name) {
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char c) {
        return c == '\\' ? '/' : static_cast<char>(std::tolower(c));
    });
    return name == "srcsrv" || name == "/srcsrv" || name == "sourcelink" ||
           name == "/sourcelink" || name.rfind("sourcelink$", 0) == 0 ||
           name.rfind("/sourcelink$", 0) == 0 || name.rfind("/src/", 0) == 0 ||
           name.rfind("src/", 0) == 0 || name.rfind("/udtsrcline", 0) == 0;
}

struct NamedStreams {
    std::size_t headerSize;
    Bytes strings;
    std::uint32_t tableSize;
    std::vector<std::uint32_t> present;
    std::vector<std::uint32_t> deleted;
    struct Entry { std::uint32_t slot, offset, stream; };
    std::vector<Entry> entries;
    std::uint32_t niMac;
    Bytes trailing;
};

NamedStreams parseNamedStreams(const Bytes& pdb) {
    for (auto headerSize : {std::size_t(28), std::size_t(12)}) {
        try {
            std::size_t cursor = headerSize;
            const auto stringSize = read32(pdb, cursor); cursor += 4;
            if (cursor + stringSize > pdb.size()) throw Error("bad named stream strings");
            NamedStreams map;
            map.headerSize = headerSize;
            map.strings.assign(pdb.begin() + cursor, pdb.begin() + cursor + stringSize);
            cursor += stringSize;
            const auto entries = read32(pdb, cursor);
            map.tableSize = read32(pdb, cursor + 4); cursor += 8;
            const auto presentWords = read32(pdb, cursor); cursor += 4;
            for (std::uint32_t i = 0; i != presentWords; ++i, cursor += 4) map.present.push_back(read32(pdb, cursor));
            const auto deletedWords = read32(pdb, cursor); cursor += 4;
            for (std::uint32_t i = 0; i != deletedWords; ++i, cursor += 4) map.deleted.push_back(read32(pdb, cursor));
            if (presentWords < (map.tableSize + 31) / 32)
                throw Error("named stream presence bitmap is too small");
            for (std::uint32_t slot = 0; slot != map.tableSize; ++slot) {
                if (map.present[slot / 32] & (1u << (slot % 32))) {
                    map.entries.push_back({slot, read32(pdb, cursor), read32(pdb, cursor + 4)});
                    cursor += 8;
                }
            }
            if (map.entries.size() != entries) throw Error("bad named stream entry count");
            map.niMac = read32(pdb, cursor); cursor += 4;
            map.trailing.assign(pdb.begin() + cursor, pdb.end());
            return map;
        } catch (const Error&) {
        }
    }
    throw Error("cannot parse named stream map");
}

std::uint32_t rewriteNamedStreams(Msf& msf, std::set<std::uint32_t>& removed) {
    Bytes pdb = msf.readStream(kPdbStream);
    NamedStreams map = parseNamedStreams(pdb);
    std::uint32_t namesStream = 0xffffffffu;
    for (auto entry : map.entries) {
        const auto end = cstringEnd(map.strings, entry.offset, map.strings.size());
        std::string name(reinterpret_cast<const char*>(map.strings.data() + entry.offset), end - entry.offset - 1);
        if (name == "/names") namesStream = entry.stream;
        if (sourceStreamName(name)) {
            removed.insert(entry.stream);
        }
    }
    return namesStream;
}

void strip(const std::filesystem::path& input, const std::filesystem::path& output) {
    if (std::filesystem::absolute(input).lexically_normal() ==
        std::filesystem::absolute(output).lexically_normal())
        throw Error("input and output must differ");
    if (std::filesystem::exists(output)) throw Error("output file already exists");
    const auto inputSize = std::filesystem::file_size(input);
    std::wcout << L"Input:  " << input << L" (" << inputSize << L" bytes)\n";
    std::wcout << L"Output: " << output << L"\n";
    std::wcout << L"Copying input to a temporary working file...\n";
    TemporaryFile temporary(output);
    TemporaryFile compact(output);
    std::filesystem::copy_file(input, temporary.path(),
                               std::filesystem::copy_options::overwrite_existing);
    const DWORD attributes = GetFileAttributesW(temporary.path().c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES ||
        !SetFileAttributesW(temporary.path().c_str(), attributes & ~FILE_ATTRIBUTE_READONLY))
        throw Error("cannot make temporary output writable");
    {
        Msf msf(temporary.path());
        std::wcout << L"DBI: removing line tables, source metadata, and path-bearing module data...\n";
        const auto dbi = rewriteDbi(msf);
        std::wcout << L"DBI: processed " << dbi.modules << L" module record(s), including "
                   << dbi.moduleStreams << L" module stream(s); found "
                   << dbi.sourceNames.size() << L" unique source filename(s).\n";

        std::wcout << L"IPI: sanitizing build arguments and UDT source-line records...\n";
        const auto ipi = sanitizeIpi(msf);
        std::wcout << L"IPI: processed " << ipi.buildInfoRecords << L" build-info record(s) and "
                   << ipi.udtSourceLineRecords << L" UDT source-line record(s); redacted "
                   << ipi.stringIdsRedacted << L" string ID(s).\n";

        std::set<std::uint32_t> removedStreams;
        const auto namesStream = rewriteNamedStreams(msf, removedStreams);
        if (removedStreams.empty())
            std::wcout << L"Named streams: no source-bearing streams found; nothing to clear.\n";
        else
            std::wcout << L"Named streams: clearing " << removedStreams.size()
                       << L" source-bearing stream(s).\n";

        if (namesStream == kNilSize)
            std::wcout << L"/names: stream not present; skipping global source-name redaction.\n";
        else if (dbi.sourceNames.empty())
            std::wcout << L"/names: no DBI source filenames found; nothing to redact.\n";
        const auto redactedNames = redactGlobalNames(msf, namesStream, dbi.sourceNames);
        if (namesStream != kNilSize && !dbi.sourceNames.empty())
            std::wcout << L"/names: redacted " << redactedNames
                       << L" matching source filename entr"
                       << (redactedNames == 1 ? L"y.\n" : L"ies.\n");

        for (auto stream : removedStreams) msf.clearStream(stream);
        std::wcout << L"Writing compact MSF output...\n";
        msf.writeCompact(compact.path());
    }
    std::filesystem::rename(compact.path(), output);
    compact.release();
    const auto outputSize = std::filesystem::file_size(output);
    std::wcout << L"Completed: " << outputSize << L" bytes";
    if (outputSize <= inputSize)
        std::wcout << L" (" << inputSize - outputSize << L" bytes smaller)";
    else
        std::wcout << L" (" << outputSize - inputSize << L" bytes larger)";
    std::wcout << L".\n";
}

} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) {
        std::wcerr << L"Usage: pdbstrip <input.pdb> <output.pdb>\n";
        return 2;
    }
    try {
        strip(argv[1], argv[2]);
        std::wcout << L"Created source-stripped PDB: " << argv[2] << L"\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "pdbstrip: " << error.what() << "\n";
        return 1;
    }
}
