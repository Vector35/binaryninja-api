#include <filesystem>
#include "KernelCacheBuilder.h"

using namespace BinaryNinja;

KernelCacheBuilder::KernelCacheBuilder(Ref<BinaryView> view)
{
	m_view = std::move(view);
	m_logger = new Logger("KernelCache.Builder", m_view->GetFile()->GetSessionId());
	m_cache = KernelCache(m_view->GetAddressSize());
}

KernelCache KernelCacheBuilder::Finalize()
{
	return std::move(m_cache);
}
