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

static void EncodeWord(byte *buf, POLYUNSIGNED n) {
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

struct VectorWriter
{
    std::vector<byte> m_buff;

    void WriteWord(POLYUNSIGNED n) {
        auto i = m_buff.size();
        m_buff.resize(i + SIZEOF_POLYWORD);
        EncodeWord(&m_buff[i], n);
    }

    void WriteBytes(const byte *ptr, size_t len) {
        m_buff.insert(m_buff.end(), ptr, ptr + len);
    }

    void Flush() {}
};

struct FDWriter
{
    TaskData *taskData;
    int fd;
    static constexpr size_t BUF_SIZE = 64 * 1024;
    byte m_buf[BUF_SIZE];
    size_t m_pos = 0;

    void WriteWord(POLYUNSIGNED n) {
        if (m_pos + SIZEOF_POLYWORD > BUF_SIZE) Flush();
        EncodeWord(m_buf + m_pos, n);
        m_pos += SIZEOF_POLYWORD;
    }

    void WriteBytes(const byte *ptr, size_t len) {
        while (len > 0) {
            size_t space = BUF_SIZE - m_pos;
            size_t chunk = std::min(len, space);
            memcpy(m_buf + m_pos, ptr, chunk);
            m_pos += chunk;
            ptr += chunk;
            len -= chunk;
            if (m_pos >= BUF_SIZE) Flush();
        }
    }

    void Flush() {
        size_t written = 0;
        while (written < m_pos) {
            ssize_t n = write(fd, m_buf + written, m_pos - written);
            if (n <= 0)
                raise_exception_string(taskData, EXC_Fail, "exportSmallToFD: write failed");
            written += n;
        }
        m_pos = 0;
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
        else if (it->second == UNASSIGNED)
            raise_exception_string(taskData, EXC_Fail, "cycle detected in exportSmall");
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
            writer.Flush();
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
                writer.WriteWord(m_index[val.AsUnsigned()]);
            }
        }

        writer.WriteWord(m_index[rootw.AsUnsigned()]);
        writer.Flush();
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
        ProcessExport<FDWriter> process{
            .taskData = taskData,
            .writer = {.taskData = taskData, .fd = (int)PolyWord::FromUnsigned(fd).UnTagged()}
        };
        process.Process(obj);
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
