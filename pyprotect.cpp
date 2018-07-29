#include <string>
#include <vector>
#include <list>
#include <fstream>

#include <unistd.h>
#include <sys/param.h>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <pybind11/eval.h>

#include "config.h"
#include "aes.h"

using namespace std;
namespace py = pybind11;
using namespace pybind11::literals;

#if defined(_WIN32)
#define OS_SEP '\\'
#else
#define OS_SEP '/'
#endif


struct ModLoader {
private:
    string filename;
    AES_ctx aesCtx;

public:
    explicit ModLoader(string filename):
        filename(move(filename))
    {
        if (sizeof(PYPROTECT_KEY) != 17 || sizeof(PYPROTECT_IV) != 17) {
            throw logic_error("load module failed");
        }

        AES_init_ctx_iv(&aesCtx, (uint8_t*)PYPROTECT_KEY, (uint8_t*)PYPROTECT_IV);
    }

    py::object create_module(const py::object& module) {
        return py::none();
    }

    void exec_module(const py::object& module) {
#ifdef DEBUG
        printf("[load] %s\n", filename.c_str());
#endif

        ifstream fsrc(filename);

        if (!fsrc.is_open()) {
            return;
        }

        std::string src((std::istreambuf_iterator<char>(fsrc)),
                        std::istreambuf_iterator<char>());

        uint8_t *buffer = nullptr;
        buffer = (uint8_t*)malloc(src.length());
        if (!buffer) {
            return;
        }
        memcpy(buffer, src.data(), src.length());
        uint32_t len = (uint32_t)src.length();

        AES_CBC_decrypt_buffer(&aesCtx, buffer, len);

        uint8_t padding = buffer[len-1];

        if (padding > 16 || padding < 0) {
#ifdef DEBUG
            printf("[error] padding=%d\n", padding);
#endif
            return;
        }

        for (int i = 0; i < padding; ++i) {
            if (buffer[len-1-i] != padding) {
                return;
            }
        }

        len -= padding;
#ifdef DEBUG
        printf("[load] python script:\n%.*s\n", len, buffer);
#endif
        py::dict d = py::dict(module.attr("__dict__"));
        d["__builtins__"] = py::module::import("builtins").attr("__dict__");
        py::exec(py::bytes((char*)buffer, len), d);

        free(buffer);
    }
};


struct ModFinder {
private:
    static py::object modLoaderClass;
    static py::object specFromFileLocation;
public:
    static void initialize(py::object mlc, py::object sfl) {
        modLoaderClass =  move(mlc);
        specFromFileLocation = move(sfl);

        // increase object ref counter to avoid "Error ... double free or corruption"
        modLoaderClass.inc_ref();
        specFromFileLocation.inc_ref();
    }
    py::object find_spec(const string &fullname, const py::object& pypath, const py::object& target) {
#ifdef DEBUG
        py::print("[find]", fullname, pypath, target);
#endif

        vector<string> path;

        if (py::isinstance<py::str>(pypath)) {
            path.push_back(pypath.cast<string>());
        } else if (!pypath.is_none()) {
            path = pypath.cast<py::list>().cast<vector<string>>();
        }

        if (path.empty()) {
            char cwd[MAXPATHLEN];
            getcwd(cwd, MAXPATHLEN);
            path = {cwd};
        }

        size_t p = fullname.find_last_of('.');
        string name;
        if (p == string::npos) {
            name = fullname;
        } else {
            name = fullname.substr(p+1);
        }

        for (auto &entry : path) {
            string filename;
            py::object submodule_search_locations = py::none();

            string fpath = entry + OS_SEP + name;

            struct stat st = {0};
            if (stat((fpath).c_str(), &st) == 0 && (st.st_mode & S_IFDIR)) {
                filename = fpath + OS_SEP + "__init__" PYPROTECT_EXT_NAME;
                if (stat(filename.c_str(), &st) != 0) {
                    continue;
                }
                py::list submodule_locations;
                submodule_locations.append(py::str(fpath));
                submodule_search_locations = submodule_locations;
            } else {
                filename = fpath + PYPROTECT_EXT_NAME;
                if (stat(filename.c_str(), &st) != 0) {
                    continue;
                }
            }
            return specFromFileLocation(fullname, filename,
                                           "loader"_a=modLoaderClass(filename),
                                           "submodule_search_locations"_a=submodule_search_locations);
        }
#ifdef DEBUG
        printf("[find] module not found '%s', '%s'\n", fullname.c_str(), name.c_str());
#endif
        return py::none();

    }
};

py::object ModFinder::modLoaderClass;
py::object ModFinder::specFromFileLocation;


PYBIND11_MODULE(libpyprotect, m) {
#ifdef DEBUG
    puts("*** libpyprotect loaded ***");
#endif
    py::class_<ModLoader>modLoaderClass(m, "ModLoader");
    modLoaderClass.def(py::init<const string &>());
    modLoaderClass.def("create_module", &ModLoader::create_module);
    modLoaderClass.def("exec_module", &ModLoader::exec_module);

    py::class_<ModFinder>modFinderClass(m, "ModFinder");
    modFinderClass.def("find_spec", &ModFinder::find_spec);

    ModFinder::initialize(modLoaderClass, py::module::import("importlib.util").attr("spec_from_file_location"));

    ModFinder* modfinder = new ModFinder();

    py::module sys = py::module::import("sys");
    py::list meta_path = sys.attr("meta_path");
    py::list new_meta_path;
    new_meta_path.append(py::cast(modfinder));

    for (auto mp : meta_path) {
        new_meta_path.append(mp);
    }
    sys.attr("meta_path") = new_meta_path;
}
