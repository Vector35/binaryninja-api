#pragma once
#include "core/binaryninja_defs.h"
#include "refcount.hpp"

namespace BinaryNinja {
	class ConfidenceBase
	{
	  protected:
		uint8_t m_confidence;

	  public:
		ConfidenceBase() : m_confidence(0) {}

		ConfidenceBase(uint8_t conf) : m_confidence(conf) {}

		static uint8_t Combine(uint8_t a, uint8_t b)
		{
			uint8_t result = (uint8_t)(((uint32_t)a * (uint32_t)b) / BN_FULL_CONFIDENCE);
			if ((a >= BN_MINIMUM_CONFIDENCE) && (b >= BN_MINIMUM_CONFIDENCE) && (result < BN_MINIMUM_CONFIDENCE))
				result = BN_MINIMUM_CONFIDENCE;
			return result;
		}

		uint8_t GetConfidence() const { return m_confidence; }
		uint8_t GetCombinedConfidence(uint8_t base) const { return Combine(m_confidence, base); }
		void SetConfidence(uint8_t conf) { m_confidence = conf; }
		bool IsUnknown() const { return m_confidence == 0; }
	};

	template <class T>
	class Confidence : public ConfidenceBase
	{
		T m_value;

	  public:
		Confidence() {}

		Confidence(const T& value) : ConfidenceBase(BN_FULL_CONFIDENCE), m_value(value) {}

		Confidence(const T& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<T>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator T() const { return m_value; }
		T* operator->() { return &m_value; }
		const T* operator->() const { return &m_value; }

		// This MUST be a copy. There are subtle compiler scoping bugs that will cause nondeterministic failures
		// when using one of these objects as a temporary if a reference is returned here. Unfortunately, this has
		// negative performance implications. Make a local copy first if the template argument is a complex
		// object and it is needed repeatedly.
		T GetValue() const { return m_value; }

		void SetValue(const T& value) { m_value = value; }

		Confidence<T>& operator=(const Confidence<T>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<T>& operator=(const T& value)
		{
			m_value = value;
			m_confidence = BN_FULL_CONFIDENCE;
			return *this;
		}

		bool operator<(const Confidence<T>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<T>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_confidence == a.m_confidence;
		}

		bool operator!=(const Confidence<T>& a) const { return !(*this == a); }
	};

	template <class T>
	class Confidence<Ref<T>> : public ConfidenceBase
	{
		Ref<T> m_value;

	  public:
		Confidence() {}

		Confidence(T* value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(T* value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Ref<T>& value) : ConfidenceBase(value ? BN_FULL_CONFIDENCE : 0), m_value(value) {}

		Confidence(const Ref<T>& value, uint8_t conf) : ConfidenceBase(conf), m_value(value) {}

		Confidence(const Confidence<Ref<T>>& v) : ConfidenceBase(v.m_confidence), m_value(v.m_value) {}

		operator Ref<T>() const { return m_value; }
		operator T*() const { return m_value.GetPtr(); }
		T* operator->() const { return m_value.GetPtr(); }
		bool operator!() const { return !m_value; }

		const Ref<T>& GetValue() const { return m_value; }
		void SetValue(T* value) { m_value = value; }
		void SetValue(const Ref<T>& value) { m_value = value; }

		Confidence<Ref<T>>& operator=(const Confidence<Ref<T>>& v)
		{
			m_value = v.m_value;
			m_confidence = v.m_confidence;
			return *this;
		}

		Confidence<Ref<T>>& operator=(T* value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		Confidence<Ref<T>>& operator=(const Ref<T>& value)
		{
			m_value = value;
			m_confidence = value ? BN_FULL_CONFIDENCE : 0;
			return *this;
		}

		bool operator<(const Confidence<Ref<T>>& a) const
		{
			if (m_value < a.m_value)
				return true;
			if (a.m_value < m_value)
				return false;
			return m_confidence < a.m_confidence;
		}

		bool operator==(const Confidence<Ref<T>>& a) const
		{
			if (m_confidence != a.m_confidence)
				return false;
			return m_confidence == a.m_confidence;
		}

		bool operator!=(const Confidence<Ref<T>>& a) const { return !(*this == a); }
	};
}