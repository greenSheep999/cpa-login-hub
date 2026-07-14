//go:build cgo && (linux || darwin)

// Package main — self-locate the plugin .dylib / .so via dladdr.
//
// CPA's pluginhost dlopens us but doesn't tell us where from. To let the
// Go side find its sibling worker/ directory we ask libdl for the path
// backing an address inside our own module. The address of the
// cliproxyPluginCall export is guaranteed to live in our library.
package main

/*
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

// Returns a caller-owned strdup'd copy of the loaded shared library
// path that contains this symbol, or NULL on error. Free with free().
static char* selfSharedLibraryPath() {
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (dladdr((void*)selfSharedLibraryPath, &info) == 0) {
        return NULL;
    }
    if (info.dli_fname == NULL) {
        return NULL;
    }
    return strdup(info.dli_fname);
}

#cgo linux LDFLAGS: -ldl
*/
import "C"

import (
	"path/filepath"
	"unsafe"
)

// selfLibraryDir returns the directory containing the plugin's own
// .dylib / .so. Empty string if resolution failed.
func selfLibraryDir() string {
	cpath := C.selfSharedLibraryPath()
	if cpath == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(cpath))
	path := C.GoString(cpath)
	if path == "" {
		return ""
	}
	// dli_fname on macOS returns the path as it was passed to dlopen —
	// which may be relative. Resolve to absolute so subsequent
	// filepath.Join calls don't get confused.
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Dir(path)
	}
	return filepath.Dir(abs)
}
