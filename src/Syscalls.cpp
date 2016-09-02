/*
 * Copyright (C) 2016 Cybernetica
 *
 * Research/Commercial License Usage
 * Licensees holding a valid Research License or Commercial License
 * for the Software may use this file according to the written
 * agreement between you and Cybernetica.
 *
 * GNU General Public License Usage
 * Alternatively, this file may be used under the terms of the GNU
 * General Public License version 3.0 as published by the Free Software
 * Foundation and appearing in the file LICENSE.GPL included in the
 * packaging of this file.  Please review the following information to
 * ensure the GNU General Public License version 3.0 requirements will be
 * met: http://www.gnu.org/copyleft/gpl-3.0.html.
 *
 * For further information, please contact us at sharemind@cyber.ee.
 */

#include <iostream>
#include <sharemind/SyscallsCommon.h>
#include <sharemind/libmodapi/api_0x1.h>
#include "ModuleData.h"

using namespace sharemind;

SHAREMIND_EXTERN_C_BEGIN

SHAREMIND_MODULE_API_0x1_SYSCALL(keydb_set,
                                 args, num_args, refs, crefs,
                                 returnValue, c)
{
    if (!SyscallArgs<0u, false, 0u, 0u>::check(num_args, refs, crefs, returnValue)) {
        return SHAREMIND_MODULE_API_0x1_INVALID_CALL;
    }
    try {
        ModuleData * mod = static_cast<ModuleData *>(c->moduleHandle);
        std::cout << "tere syscall " << mod->configuration << std::endl;
        return SHAREMIND_MODULE_API_0x1_OK;
    } catch (const std::bad_alloc &) {
        return SHAREMIND_MODULE_API_0x1_OUT_OF_MEMORY;
    } catch (...) {
        return SHAREMIND_MODULE_API_0x1_MODULE_ERROR;
    }
}

SHAREMIND_EXTERN_C_END
