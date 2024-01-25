
#pragma once

#include <zeek/plugin/Plugin.h>
#include "Conn.h"
#include "zeek/Conn.h"
#include "zeek/analyzer/Component.h"
// #include "zeek/analyzer/Component.h"
#include "zeek/analyzer/Analyzer.h"

namespace plugin {
namespace TCPExtractor_UrgentPointerExtractor {

	class Plugin : public zeek::plugin::Plugin
	{
		protected:
			// Overridden from zeek::plugin::Plugin.
			zeek::plugin::Configuration Configure() override;
			// virtual void HookSetupAnalyzerTree(zeek::Connection *conn);
	};

	extern Plugin plugin;

	}
}
