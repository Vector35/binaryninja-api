/*
Copyright 2020-2026 Vector 35 Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#pragma once

// intx provides the wide-integer type used throughout the emulator plugin's core and
// API. It lives here (rather than in binaryninjaapi.h) so it is only pulled in by the
// emulator's own headers. If a translation unit includes <windows.h> before this header
// (as several debugger adapters do), its min/max macros would break intx's
// numeric_limits<>::min()/max() member definitions. Neutralize those macros just for the
// intx include, then restore them so any later code relying on windows.h min/max is
// unaffected.
#if defined(_WIN32)
	#pragma push_macro("min")
	#pragma push_macro("max")
	#undef min
	#undef max
#endif
#include "vendor/intx/intx.hpp"
#if defined(_WIN32)
	#pragma pop_macro("min")
	#pragma pop_macro("max")
#endif
