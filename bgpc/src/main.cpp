#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
//#include <pybind11/optional.h>
#include "enums.hpp"
#include "announcement.hpp"
#include "local_rib.hpp"
#include "recv_queue.hpp"
#include "policy.hpp"
#include "bgp_simple_policy.hpp"
#include "as.hpp"
#include "as_graph.hpp"
#include "cpp_simulation_engine.hpp"
#include "utils.hpp"
#include "as_graph_analyzer.hpp"


#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <string>
#include <functional>
#include <chrono>
#include <iomanip>
#include <memory>
#include <algorithm>
#include <optional>
#include <stdexcept> // for std::runtime_error
#include <set>
#include <type_traits>  // for std::is_base_of


// Disable threading since we don't use it
// drastically improves weak pointer times...
//https://stackoverflow.com/a/8966130
//weak pointer is still slow according to this https://stackoverflow.com/a/35137265
//althought hat doesn't show the BOOST_DISBALE_THREADS
//I replicated the results, it's about 2x as slow
//Still, for good design, since I'm terrible at C++, I'm keeping it
//esp since it's probably negligable since this timing test
//was with 100000000U times
#define BOOST_DISABLE_THREADS


// Helper function to combine hash values
void hash_combine(std::size_t& seed, std::size_t hash) {
    seed ^= hash + 0x9e3779b9 + (seed << 6) + (seed >> 2);
}

// Function to hash a vector
template <class T>
std::size_t hash_vector(const std::vector<T>& v) {
    std::size_t seed = 0;
    for (const T& i : v) {
        hash_combine(seed, std::hash<T>()(i));
    }
    return seed;
}

// Function to hash std::optional
template <typename T>
std::size_t hash_optional(const std::optional<T>& opt) {
    return opt ? std::hash<T>()(*opt) : 0;
}

// Define the std::hash specialization for Announcement
namespace std {
    template<> struct hash<Announcement> {
        size_t operator()(const Announcement& a) const {
            std::size_t seed = 0;

            // Hash simple types directly
            hash_combine(seed, std::hash<unsigned short int>()(a.prefix_block_id));
            hash_combine(seed, std::hash<Relationships>()(a.recv_relationship));
            hash_combine(seed, std::hash<bool>()(a.traceback_end));

            // Hash all elements of as_path 
            hash_combine(seed, hash_vector(a.as_path));

            // Hash shared_ptr content if it exists
            if (a.staticData) {
                hash_combine(seed, std::hash<std::string>()(a.staticData->prefix));
                hash_combine(seed, std::hash<int>()(a.staticData->timestamp));
                hash_combine(seed, hash_optional(a.staticData->seed_asn));
                hash_combine(seed, hash_optional(a.staticData->roa_valid_length));
                hash_combine(seed, hash_optional(a.staticData->roa_origin));
                hash_combine(seed, std::hash<bool>()(a.staticData->withdraw));
            }

            return seed;
        }
    };
}

int main() {
    try {
        auto engine = get_engine();
        // Get announcements from TSV file
        std::vector<std::shared_ptr<Announcement>> announcements = get_announcements_from_tsv();
        // Setup the engine with the loaded announcements
        engine.setup(
            announcements,
            "BGPSimplePolicy",
            {},
            1000
        );
        engine.run();
        std::cout << "done" << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

namespace py = pybind11;
#define PYBIND11_DETAILED_ERROR_MESSAGES

PYBIND11_MODULE(bgpc, m) {
    m.def("main", &main, "what is this desc for?");
    m.def("get_engine", &get_engine, py::arg("filename") = "/home/anon/Desktop/caida.tsv");
    py::enum_<Relationships>(m, "Relationships")
        .value("PROVIDERS", Relationships::PROVIDERS)
        .value("PEERS", Relationships::PEERS)
        .value("CUSTOMERS", Relationships::CUSTOMERS)
        .value("ORIGIN", Relationships::ORIGIN)
        .value("UNKNOWN", Relationships::UNKNOWN)
        .export_values();
    py::enum_<Outcomes>(m, "Outcomes")
        .value("ATTACKER_SUCCESS", Outcomes::ATTACKER_SUCCESS)
        .value("VICTIM_SUCCESS", Outcomes::VICTIM_SUCCESS)
        .value("DISCONNECTED", Outcomes::DISCONNECTED)
        .value("UNDETERMINED", Outcomes::UNDETERMINED)
        .export_values();

    py::class_<CPPSimulationEngine, std::shared_ptr<CPPSimulationEngine>>(m, "CPPSimulationEngine")
        .def("setup", &CPPSimulationEngine::setup, py::arg("announcements"), py::arg("base_policy_class_str") = "BGPSimplePolicy", py::arg("non_default_asn_cls_str_dict") = std::unordered_map<int, std::string>{}, py::arg("max_prefix_block_id") = 0)
        .def("run", &CPPSimulationEngine::run,
             py::arg("propagation_round") = 0)
        .def("dump_local_ribs_to_tsv", &CPPSimulationEngine::dump_local_ribs_to_tsv,
             py::arg("tsv_path"))
        .def("get_announcements", &CPPSimulationEngine::get_announcements);
        /*
        .def("setup", [](CPPSimulationEngine& engine, const std::vector<std::shared_ptr<Announcement>>& announcements, const std::string& base_policy_class_str, const std::map<int, std::string>& non_default_asn_cls_str_dict) {
            // Debug: Print the number of announcements
            std::cout << "Setting up engine with " << announcements.size() << " announcements." << std::endl;

            // Check for null pointers
            for (const auto& ann : announcements) {
                if (!ann) {
                    throw std::runtime_error("Null announcement in the list");
                }
            }
            // Call the actual setup method
            engine.setup(announcements, base_policy_class_str, non_default_asn_cls_str_dict);
        }, py::arg("announcements"), py::arg("base_policy_class_str") = "BGPSimplePolicy", py::arg("non_default_asn_cls_str_dict") = std::map<int, std::string>{})
       */

    py::class_<ASGraphAnalyzer>(m, "ASGraphAnalyzer")
        .def(py::init<std::shared_ptr<CPPSimulationEngine>,
                      const std::vector<unsigned short int>&,
                      const std::unordered_set<int>&,
                      const std::unordered_set<int>&,
                      bool,
                      bool>(),
             py::arg("engine"),
             py::arg("ordered_prefixes"),
             py::arg("victim_asns"),
             py::arg("attacker_asns"),
             py::arg("data_plane_tracking") = true,
             py::arg("control_plane_tracking") = false)
        .def("analyze", &ASGraphAnalyzer::analyze);
    /*
    py::class_<Announcement, std::shared_ptr<Announcement>>(m, "Announcement")
        .def(py::init<const std::string&, const std::vector<int>&, int,
                      const std::optional<int>&, const std::optional<bool>&,
                      const std::optional<int>&, Relationships, bool, bool,
                      const std::vector<std::string>&>(),
             py::arg("prefix"), py::arg("as_path"), py::arg("timestamp"),
             py::arg("seed_asn") = std::nullopt, py::arg("roa_valid_length") = std::nullopt,
             py::arg("roa_origin") = std::nullopt,
             py::arg("recv_relationship") = Relationships::UNKNOWN,  // Default value for recv_relationship
             py::arg("withdraw") = false,                             // Default value for withdraw
             py::arg("traceback_end") = false,                        // Default value for traceback_end
             py::arg("communities") = std::vector<std::string>{})     // Default value for communities
        .def_readonly("prefix", &Announcement::prefix)
        .def_readonly("as_path", &Announcement::as_path)
        .def_readonly("timestamp", &Announcement::timestamp)
        .def_readonly("seed_asn", &Announcement::seed_asn)
        .def_readonly("roa_valid_length", &Announcement::roa_valid_length)
        .def_readonly("roa_origin", &Announcement::roa_origin)
        .def_readonly("recv_relationship", &Announcement::recv_relationship)
        .def_readonly("withdraw", &Announcement::withdraw)
        .def_readonly("traceback_end", &Announcement::traceback_end)
        .def_readonly("communities", &Announcement::communities)
        .def("prefix_path_attributes_eq", &Announcement::prefix_path_attributes_eq)
        .def_property_readonly("invalid_by_roa", &Announcement::invalid_by_roa)
        .def_property_readonly("valid_by_roa", &Announcement::valid_by_roa)
        .def_property_readonly("unknown_by_roa", &Announcement::unknown_by_roa)
        .def_property_readonly("covered_by_roa", &Announcement::covered_by_roa)
        .def_property_readonly("roa_routed", &Announcement::roa_routed)
        .def_property_readonly("origin", &Announcement::origin)
        .def("__eq__", [](const Announcement &self, const Announcement &other) {
            return self == other;
        });
     */
    py::class_<Announcement, std::shared_ptr<Announcement>>(m, "Announcement")
        .def(py::init<const unsigned short int,
                      const std::string&, const std::vector<int>&, int,
                      const std::optional<int>&, const std::optional<bool>&,
                      const std::optional<int>&, Relationships, bool, bool,
                      const std::vector<std::string>&>(),
             py::arg("prefix_block_id"),
             py::arg("prefix"), py::arg("as_path"), py::arg("timestamp"),
             py::arg("seed_asn") = std::nullopt, py::arg("roa_valid_length") = std::nullopt,
             py::arg("roa_origin") = std::nullopt,
             py::arg("recv_relationship") = Relationships::UNKNOWN,  // Default value for recv_relationship
             py::arg("withdraw") = false,                             // Default value for withdraw
             py::arg("traceback_end") = false,                        // Default value for traceback_end
             py::arg("communities") = std::vector<std::string>{})     // Default value for communities
        .def_readonly("prefix_block_id", &Announcement::prefix_block_id)
        .def_property_readonly("prefix", &Announcement::prefix)
        .def_readonly("as_path", &Announcement::as_path)
        .def_property_readonly("timestamp", &Announcement::timestamp)
        .def_property_readonly("seed_asn", &Announcement::seed_asn)
        .def_property_readonly("roa_valid_length", &Announcement::roa_valid_length)
        .def_property_readonly("roa_origin", &Announcement::roa_origin)
        .def_readonly("recv_relationship", &Announcement::recv_relationship)
        .def_property_readonly("withdraw", &Announcement::withdraw)
        .def_readonly("traceback_end", &Announcement::traceback_end)
        //.def_readonly("communities", &Announcement::communities)
        .def("prefix_path_attributes_eq", &Announcement::prefix_path_attributes_eq)
        .def_property_readonly("invalid_by_roa", &Announcement::invalid_by_roa)
        .def_property_readonly("valid_by_roa", &Announcement::valid_by_roa)
        .def_property_readonly("unknown_by_roa", &Announcement::unknown_by_roa)
        .def_property_readonly("covered_by_roa", &Announcement::covered_by_roa)
        .def_property_readonly("roa_routed", &Announcement::roa_routed)
        .def_property_readonly("origin", &Announcement::origin)
        .def("__eq__", [](const Announcement &self, const Announcement &other) {
            return self == other;
        })
        .def("__hash__", [](const Announcement &a) {
            return std::hash<Announcement>()(a);
        });
}
