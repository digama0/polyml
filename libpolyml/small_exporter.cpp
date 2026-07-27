/*
    Title:  small_exporter.cpp - Export simple data values in a binary format

    Copyright (c) 2024 Mario Carneiro

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License version 2.1 as published by the Free Software Foundation.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_WIN32)
#include "winconfig.h"
#else
#error "No configuration file"
#endif

#ifdef HAVE_ASSERT_H
#include <assert.h>
#define ASSERT(x) assert(x)

#else
#define ASSERT(x)
#endif

#include <vector>
#include <unordered_map>
#include <algorithm>
#include <cstring>

#include "polystring.h"
#include "scanaddrs.h"
#include "machine_dep.h"
#include "processes.h"
#include "rtsentry.h"
#include "bitmap.h"
#include "sys.h"
#include "run_time.h"
#include "io_internal.h"

#if (defined(_WIN32))
#define NOMEMORY ERROR_NOT_ENOUGH_MEMORY
#define ERRORNUMBER _doserrno
#else
#include <unistd.h>
#define NOMEMORY ENOMEM
#define ERRORNUMBER errno
#endif

extern "C" {
    POLYEXTERNALSYMBOL POLYUNSIGNED PolySmallExport(POLYUNSIGNED threadId, POLYUNSIGNED root);
    POLYEXTERNALSYMBOL POLYUNSIGNED PolySmallExportToFD(POLYUNSIGNED threadId, POLYUNSIGNED fd, POLYUNSIGNED root);
}

#define UNASSIGNED (POLYUNSIGNED)-(1 << POLY_TAGSHIFT)

static bool IsLittleEndian() {
    uint16_t number = 0x1;
    return *reinterpret_cast<uint8_t*>(&number) == 0x1;
}

// Encode `n` to the buffer as 4 or 8 byte little endian.
static void EncodeWord(byte *buf, POLYUNSIGNED n) {
    if (IsLittleEndian()) {
        std::memcpy(buf, &n, sizeof(POLYUNSIGNED));
    } else {
        buf[0] = (byte)(n & 0xFF);
        buf[1] = (byte)((n >> 8) & 0xFF);
        buf[2] = (byte)((n >> 16) & 0xFF);
        buf[3] = (byte)((n >> 24) & 0xFF);
#if (SIZEOF_POLYWORD == 8)
        buf[4] = (byte)((n >> 32) & 0xFF);
        buf[5] = (byte)((n >> 40) & 0xFF);
        buf[6] = (byte)((n >> 48) & 0xFF);
        buf[7] = (byte)((n >> 56) & 0xFF);
#else
        ASSERT(SIZEOF_POLYWORD == 4);
#endif
    }
}

struct VectorWriter
{
    std::vector<byte> m_buff;
    std::vector<size_t> m_holes;

    void WriteWord(POLYUNSIGNED n) {
        size_t i = m_buff.size();
        m_buff.resize(i + SIZEOF_POLYWORD);
        EncodeWord(&m_buff[i], n);
    }

    void WriteBytes(const byte *ptr, size_t len) {
        m_buff.insert(m_buff.end(), ptr, ptr + len);
    }

    void AddHole(POLYUNSIGNED targetAddr) {
        size_t i = m_buff.size();
        m_holes.push_back(i);
        m_buff.resize(i + SIZEOF_POLYWORD);
        // write hole in native endian (possibly unaligned write)
        std::memcpy(&m_buff[i], &targetAddr, sizeof(POLYUNSIGNED));
    }

    void ResolveHoles(POLYUNSIGNED, POLYUNSIGNED) {}

    void ResolveAllHoles(std::unordered_map<POLYUNSIGNED, POLYUNSIGNED>& indices) {
        for (size_t offset : m_holes) {
            byte* hole = &m_buff[offset];
            POLYUNSIGNED holeVal;
            // read hole in native endian (possibly unaligned read)
            std::memcpy(&holeVal, hole, sizeof(POLYUNSIGNED));
            EncodeWord(hole, indices[holeVal]); // write final value in little endian
        }
    }
};

struct FDWriter
{
    TaskData *taskData;
    int fd;
    static const size_t BUF_SIZE = 64 * 1024;
    std::vector<byte> m_buff;
    size_t m_base;
    std::vector<size_t> m_holes;

    void WriteAll(const byte *ptr, size_t len) {
        while (len != 0) {
            ssize_t n = write(fd, ptr, len);
            if (n <= 0)
                raise_exception_string(taskData, EXC_Fail, "exportSmallToFD: write failed");
            len -= n;
            ptr += n;
        }
    }

    void WriteWord(POLYUNSIGNED n) {
        size_t pos = m_buff.size();
        m_buff.resize(pos + SIZEOF_POLYWORD);
        EncodeWord(&m_buff[pos], n);
        if (m_holes.empty() && pos + SIZEOF_POLYWORD >= BUF_SIZE) Flush();
    }

    void WriteBytes(const byte *ptr, size_t len) {
        if (m_holes.empty()) {
            if (len > BUF_SIZE) {
                Flush();
                WriteAll(ptr, len);
                m_base += len;
            } else {
                size_t pos = m_buff.size();
                m_buff.resize(pos + len);
                memcpy(&m_buff[pos], ptr, len);
                if (pos + len >= BUF_SIZE) Flush();
            }
        } else {
            size_t pos = m_buff.size();
            m_buff.resize(pos + len);
            memcpy(&m_buff[pos], ptr, len);
        }
    }

    void AddHole(POLYUNSIGNED targetAddr) {
        m_holes.push_back(m_base + m_buff.size());
        size_t pos = m_buff.size();
        m_buff.resize(pos + SIZEOF_POLYWORD);
        // write hole in native endian (possibly unaligned write)
        std::memcpy(&m_buff[pos], &targetAddr, sizeof(POLYUNSIGNED));
    }

    void ResolveHoles(POLYUNSIGNED targetAddr, POLYUNSIGNED finalIndex) {
        if (m_holes.empty()) return;

        size_t firstHoleBefore = m_holes[0];

        m_holes.erase(std::remove_if(m_holes.begin(), m_holes.end(), [&](size_t holeOffset) {
            byte* hole = &m_buff[holeOffset - m_base];
            POLYUNSIGNED holeVal;
            // read hole in native endian (possibly unaligned read)
            std::memcpy(&holeVal, hole, sizeof(POLYUNSIGNED));
            if (holeVal != targetAddr) return false;
            EncodeWord(hole, finalIndex); // write final value in little endian
            return true; // remove hole
        }), m_holes.end());

        if (m_holes.empty()) {
            if (m_buff.size() >= BUF_SIZE) Flush();
        } else if (m_holes[0] != firstHoleBefore) {
            size_t len = m_holes[0] - m_base;
            // don't actually flush unless it's worth it
            if (len < BUF_SIZE || m_buff.size() / 16 >= len) return;
            WriteAll(m_buff.data(), len);
            m_buff.erase(m_buff.begin(), m_buff.begin() + len);
            m_base += len;
        }
    }

    void ResolveAllHoles(std::unordered_map<POLYUNSIGNED, POLYUNSIGNED>&) {}

    void Flush() {
        ASSERT(m_holes.empty());
        if (!m_buff.empty()) {
            WriteAll(m_buff.data(), m_buff.size());
            m_base += m_buff.size();
            m_buff.clear();
        }
    }
};

template<typename Writer>
struct ProcessExport
{
    TaskData *taskData;
    Writer writer;
    std::vector<POLYUNSIGNED> m_stack;
    std::unordered_map<POLYUNSIGNED, POLYUNSIGNED> m_index;

    void ScanObjectAddress(PolyWord w) {
        auto it = m_index.find(w.AsUnsigned());
        if (it == m_index.end())
            m_stack.push_back(w.AsUnsigned());
    }

    void ScanAddressesInObjectDirect(PolyObject *obj) {
        POLYUNSIGNED lengthWord = obj->LengthWord();
        ASSERT (OBJ_IS_LENGTH(lengthWord));

        if (OBJ_IS_BYTE_OBJECT(lengthWord))
            return; /* Nothing more to do */

        if (OBJ_IS_CODE_OBJECT(lengthWord)) {
            // raise_exception_string(taskData, EXC_Fail, "can't export code objects");
            return;
        }

        if (OBJ_IS_CLOSURE_OBJECT(lengthWord)) {
            // raise_exception_string(taskData, EXC_Fail, "can't export closures");
            return;
        }

        PolyWord *end = (PolyWord*)obj + OBJ_OBJECT_LENGTH(lengthWord);
        for (PolyWord *pt = (PolyWord*)obj; pt < end; pt++) {
            PolyWord val = *pt;
            if (IS_INT(val) || val == PolyWord::FromUnsigned(0))
                continue; // Don't need to look at this.
            ASSERT(val.IsDataPtr());
            ScanObjectAddress(val);
        }
    }

    void Process(POLYUNSIGNED root) {
        PolyWord rootw = PolyWord::FromUnsigned(root);
        if (rootw.IsTagged()) {
            writer.WriteWord(rootw.AsUnsigned());
            return;
        }
        ASSERT(rootw.IsDataPtr());

        m_stack.push_back(root);

        POLYUNSIGNED curr = 0;
        while (!m_stack.empty()) {
            POLYUNSIGNED w = m_stack.back();
            PolyObject *obj = PolyWord::FromUnsigned(w).AsObjPtr();
            auto it = m_index.find(w);
            if (it != m_index.end() && it->second != UNASSIGNED) {
                m_stack.pop_back();
                continue;
            }

            size_t ostack = m_stack.size();
            ScanAddressesInObjectDirect(obj);
            if (m_stack.size() != ostack) {
                m_index[w] = UNASSIGNED;
                continue;
            }

            POLYUNSIGNED lengthWord = obj->LengthWord();
            ASSERT (OBJ_IS_LENGTH(lengthWord));

            bool isCodeOrClosure = OBJ_IS_CODE_OBJECT(lengthWord) || OBJ_IS_CLOSURE_OBJECT(lengthWord);
            if (isCodeOrClosure) {
                // Mask out the original length and set it to 0, but keep the original flags
                lengthWord &= _OBJ_PRIVATE_FLAGS_MASK;
            }

            writer.WriteWord(lengthWord);

            curr += 1 << POLY_TAGSHIFT;
            m_index[w] = curr;

            if (isCodeOrClosure) {
                // raise_exception_string(taskData, EXC_Fail, "can't export code objects");
                continue;
            }

            size_t length = OBJ_OBJECT_LENGTH(lengthWord);
            if (OBJ_IS_BYTE_OBJECT(lengthWord)) {
                writer.WriteBytes(obj->AsBytePtr(), length * sizeof(PolyWord));
                continue;
            }

            PolyWord *end = obj->AsWordPtr() + length;
            for (PolyWord *pt = obj->AsWordPtr(); pt < end; pt++) {
                PolyWord val = *pt;
                if (IS_INT(val) || val == PolyWord::FromUnsigned(0)) {
                    writer.WriteWord(val.AsUnsigned());
                    continue;
                }
                ASSERT(val.IsDataPtr());
                POLYUNSIGNED target = val.AsUnsigned();
                POLYUNSIGNED value = m_index[target];
                if (value == UNASSIGNED) { // cycle!
                    writer.AddHole(target);
                } else {
                    writer.WriteWord(value);
                }
            }

            writer.ResolveHoles(w, curr);
        }

        writer.ResolveAllHoles(m_index);

        writer.WriteWord(m_index[rootw.AsUnsigned()]);
    }
};

// RTS call: export to Word8Vector
POLYUNSIGNED PolySmallExport(POLYUNSIGNED threadId, POLYUNSIGNED obj)
{
    TaskData *taskData = TaskData::FindTaskForId(threadId);
    ASSERT(taskData != 0);
    taskData->PreRTSCall();
    Handle reset = taskData->saveVec.mark();
    Handle result = 0;

    try {
        ProcessExport<VectorWriter> process{.taskData = taskData};
        process.Process(obj);

        result = taskData->saveVec.push(
            C_string_to_Poly(taskData, (const char*)process.writer.m_buff.data(), process.writer.m_buff.size()));
    } catch (...) { } // If an ML exception is raised

    taskData->saveVec.reset(reset);
    taskData->PostRTSCall();
    if (result == 0) return TAGGED(0).AsUnsigned();
    else return result->Word().AsUnsigned();
}

// RTS call: export directly to file descriptor
POLYUNSIGNED PolySmallExportToFD(POLYUNSIGNED threadId, POLYUNSIGNED fd, POLYUNSIGNED obj)
{
    TaskData *taskData = TaskData::FindTaskForId(threadId);
    ASSERT(taskData != 0);
    taskData->PreRTSCall();
    Handle reset = taskData->saveVec.mark();

    try {
        int fdInt = getStreamFileDescriptor(taskData, PolyWord::FromUnsigned(fd));
        ProcessExport<FDWriter> process{
            .taskData = taskData,
            .writer = {.taskData = taskData, .fd = fdInt, .m_base = 0}
        };
        process.Process(obj);
        process.writer.Flush();
    } catch (...) { } // If an ML exception is raised

    taskData->saveVec.reset(reset);
    taskData->PostRTSCall();
    return TAGGED(0).AsUnsigned();
}

struct _entrypts smallExporterEPT[] =
{
    { "PolySmallExport",       (polyRTSFunction)&PolySmallExport},
    { "PolySmallExportToFD",   (polyRTSFunction)&PolySmallExportToFD},

    { NULL, NULL} // End of list.
};
