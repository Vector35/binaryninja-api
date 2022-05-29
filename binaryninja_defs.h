#pragma once

#ifdef __GNUC__
	#ifdef BINARYNINJACORE_LIBRARY
		#define BINARYNINJACOREAPI __attribute__((visibility("default")))
	#else
		#define BINARYNINJACOREAPI
	#endif
	#define BINARYNINJAPLUGIN __attribute__((visibility("default")))
#else
	#ifdef _MSC_VER
		#ifndef DEMO_VERSION
			#ifdef BINARYNINJACORE_LIBRARY
				#define BINARYNINJACOREAPI __declspec(dllexport)
			#else
				#define BINARYNINJACOREAPI
			#endif
			#define BINARYNINJAPLUGIN __declspec(dllexport)
		#else
			#define BINARYNINJACOREAPI
			#define BINARYNINJAPLUGIN
		#endif
	#else
		#define BINARYNINJACOREAPI
	#endif
#endif

#define BN_FULL_CONFIDENCE      255
#define BN_MINIMUM_CONFIDENCE   1
#define BN_DEFAULT_CONFIDENCE   96
#define BN_HEURISTIC_CONFIDENCE 192
#define BN_DEBUGINFO_CONFIDENCE 200