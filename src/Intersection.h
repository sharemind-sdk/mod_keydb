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

#ifndef SHAREMIND_MOD_KEYDB_INTERSECTION_H
#define SHAREMIND_MOD_KEYDB_INTERSECTION_H

#include <sharemind/libconsensusservice.h>
#include <sharemind/libprocessfacility.h>
#include <sharemind/module-apis/api_0x1.h>
#include <sharemind/visibility.h>
#include <string>
#include <vector>

namespace sharemind {

extern SharemindOperationType const intersectionOperation;

// keys must be sorted!
bool intersection(const std::vector<std::string> & keys,
        std::vector<std::string> & toDelete,
        const SharemindModuleApi0x1SyscallContext * c,
        SharemindProcessFacility const & processFacility)
    SHAREMIND_VISIBILITY_HIDDEN;

} /* namespace sharemind { */

#endif /* SHAREMIND_MOD_KEYDB_INTERSECTION_H */
