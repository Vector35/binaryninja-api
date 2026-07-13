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

#include <stddef.h>
#include <atomic>

namespace BinaryNinjaEmulator
{
	// Plugin-side reference-counted base, mirroring core's RefCountObject. Objects handed
	// across the C ABI keep an API-side reference; the last Release() deletes the object.
	class EmuRefCountObject
	{
	public:
		std::atomic<int> m_refs;
		EmuRefCountObject() : m_refs(0) {}
		virtual ~EmuRefCountObject() {}

		void AddRef() { m_refs.fetch_add(1); }

		void Release()
		{
			if (m_refs.fetch_sub(1) == 1)
				delete this;
		}

		void AddAPIRef() { AddRef(); }
		void ReleaseAPIRef() { Release(); }
	};


	// Macro-like helpers to hand referenced objects across the external C ABI.
	template <class T>
	static typename T::APIHandle EMU_API_OBJECT_REF(T* obj)
	{
		if (obj == nullptr)
			return nullptr;
		obj->AddAPIRef();
		return obj->GetAPIObject();
	}

	template <class T>
	static T* EMU_API_OBJECT_NEW_REF(T* obj)
	{
		if (obj)
			obj->object->AddAPIRef();
		return obj;
	}

	template <class T>
	static void EMU_API_OBJECT_FREE(T* obj)
	{
		if (obj)
			obj->object->ReleaseAPIRef();
	}
}  // namespace BinaryNinjaEmulator
