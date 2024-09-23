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
#define NOMEMORY ENOMEM
#define ERRORNUMBER errno
#endif

extern "C" {
    POLYEXTERNALSYMBOL POLYUNSIGNED PolySmallExport(POLYUNSIGNED threadId, POLYUNSIGNED root);
}

#define UNASSIGNED (POLYUNSIGNED)-(1 << POLY_TAGSHIFT)

struct ProcessExportAddresses
{
    // Encode `n` to the buffer as 4 or 8 byte little endian.
    void WriteWord(POLYUNSIGNED n) {
        auto i = m_buff.size();
        m_buff.resize(i + SIZEOF_POLYWORD);
        OverwriteWord(&m_buff[i], n);
    }

    // Encode `n` to the buffer as 4 or 8 byte little endian.
    void OverwriteWord(byte *buf, POLYUNSIGNED n) {
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

    void ScanObjectAddress(PolyWord w) {
        auto it = m_index.find(w.AsUnsigned());
        if (it == m_index.end())
            m_stack.push_back(w.AsUnsigned());
        else if (it->second == UNASSIGNED)
            m_stack.push_back(w.AsUnsigned() | 1); // cycle!
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
            WriteWord(rootw.AsUnsigned());
            return;
        }
        ASSERT(rootw.IsDataPtr());

        m_stack.push_back(root);

        std::vector<size_t> cycles;
        POLYUNSIGNED curr = 0;
        while (!m_stack.empty()) {
            POLYUNSIGNED w = m_stack.back();
            bool cycle = (w & 1) != 0;
            w &= ~1;
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

            curr += 1 << POLY_TAGSHIFT;
            m_index[w] = curr;

            POLYUNSIGNED lengthWord = obj->LengthWord();
            ASSERT (OBJ_IS_LENGTH(lengthWord));
            WriteWord(lengthWord);

            size_t length = OBJ_OBJECT_LENGTH(lengthWord);
            if (OBJ_IS_BYTE_OBJECT(lengthWord)) {
                byte *ptr = obj->AsBytePtr();
                m_buff.insert(m_buff.end(), ptr, ptr + length * sizeof(PolyWord));
                continue;
            }

            if (OBJ_IS_CODE_OBJECT(lengthWord)) {
                // raise_exception_string(taskData, EXC_Fail, "can't export code objects");
                continue;
            }

            if (OBJ_IS_CLOSURE_OBJECT(lengthWord)) {
                // raise_exception_string(taskData, EXC_Fail, "can't export closures");
                continue;
            }

            if (cycle && length != 0)
                cycles.push_back(m_stack.size());

            PolyWord *end = obj->AsWordPtr() + length;
            for (PolyWord *pt = obj->AsWordPtr(); pt < end; pt++) {
                PolyWord val = *pt;
                if (IS_INT(val) || val == PolyWord::FromUnsigned(0)) {
                    WriteWord(val.AsUnsigned());
                    continue;
                }
                ASSERT(val.IsDataPtr());
                WriteWord(cycle ? val.AsUnsigned() : m_index[val.AsUnsigned()]);
            }
        }

        for (size_t i : cycles) {
            PolyObject *obj = (PolyObject*)&m_buff[i];
            POLYUNSIGNED lengthWord = obj->LengthWord();
            PolyWord *end = obj->AsWordPtr() + OBJ_OBJECT_LENGTH(lengthWord);
            for (PolyWord *pt = obj->AsWordPtr(); pt < end; pt++) {
                PolyWord val = *pt;
                if (IS_INT(val) || val == PolyWord::FromUnsigned(0)) 
                    continue;
                OverwriteWord((byte*)pt, m_index[val.AsUnsigned()]);
            }
        }

        WriteWord(m_index[rootw.AsUnsigned()]);
    }

    TaskData *taskData;
    std::vector<byte> m_buff;
    std::vector<POLYUNSIGNED> m_stack;
    std::unordered_map<POLYUNSIGNED, POLYUNSIGNED> m_index;
};

// RTS call entry.
POLYUNSIGNED PolySmallExport(POLYUNSIGNED threadId, POLYUNSIGNED obj)
{
    TaskData *taskData = TaskData::FindTaskForId(threadId);
    ASSERT(taskData != 0);
    taskData->PreRTSCall();
    Handle reset = taskData->saveVec.mark();
    Handle result = 0;

    try {
        ProcessExportAddresses process{.taskData = taskData};
        process.Process(obj);

        result = taskData->saveVec.push(
            C_string_to_Poly(taskData, (const char*)process.m_buff.data(), process.m_buff.size()));
    } catch (...) { } // If an ML exception is raised

    taskData->saveVec.reset(reset);
    taskData->PostRTSCall();
    if (result == 0) return TAGGED(0).AsUnsigned();
    else return result->Word().AsUnsigned();
}

struct _entrypts smallExporterEPT[] =
{
    { "PolySmallExport",       (polyRTSFunction)&PolySmallExport},

    { NULL, NULL} // End of list.
};
