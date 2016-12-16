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

#include <boost/property_tree/ini_parser.hpp>
#include <boost/property_tree/ptree.hpp>
#include <sstream>

#include "Intersection.h"
#include "ModuleData.h"

namespace pt = boost::property_tree;

namespace sharemind {

ModuleData::ModuleData(const LogHard::Logger & logger, SharemindConsensusFacility * cf)
    : logger{logger}
    , consensusFacility(cf)
{
    if (consensusFacility)
        consensusFacility->add_operation_type(consensusFacility, &intersectionOperation);
}

bool ModuleData::load(const char * filename, std::string & errorMsg) {
    // Define the configuration property tree:
    pt::ptree config;

    // Parse the configuration file into the property tree:
    try {
        pt::read_ini(filename, config);
        for (const pt::ptree::value_type & v : config) {
            std::string const & section{v.first};
            if (section.find("Host") == 0u) {
                std::string name = v.second.get<std::string>("Name");
                hostMap.emplace(
                        name,
                        HostConfiguration{
                            v.second.get<std::string>("Hostname"),
                            v.second.get<std::uint16_t>("Port", 6379),
                            v.second.get<std::uint16_t>("ScanCount", 25),
                            v.second.get<bool>("DisableOverwrite", false)
                            });
            }
        }
    } catch (const pt::ini_parser_error & error) {
#if BOOST_VERSION <= 104200
        errorMsg = error.what();
#else
        std::ostringstream o;
        o << error.message() << " [" << error.filename() << ":" << error.line() << "].";
        errorMsg = o.str();
#endif
        return false;
    } catch (const pt::ptree_bad_data & error) {
        std::ostringstream o;
        o << "Bad data: " << error.what();
        errorMsg = o.str();
        return false;
    } catch (const pt::ptree_bad_path & error) {
        std::ostringstream o;
        o << "Bad path: " << error.what();
        errorMsg = o.str();
        return false;
    }

    if (hostMap.empty()) {
        errorMsg = "No hosts defined!";
        return false;
    }

    return true;
}

} /* namespace sharemind { */
