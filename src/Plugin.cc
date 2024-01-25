#include "Plugin.h"
#include "zeek/plugin/Plugin.h"
#include "URG_parser.h"

#include <cassert>

#include "zeek/Conn.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/Func.h"
#include "zeek/Val.h"
#include "zeek/input.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/Manager.h"
#include "zeek/threading/SerialTypes.h"

namespace plugin { namespace TCPExtractor_UrgentPointerExtractor { Plugin plugin; } }

using namespace plugin::TCPExtractor_UrgentPointerExtractor;

zeek::plugin::Configuration Plugin::Configure()
	{
	AddComponent(new zeek::analyzer::Component("URG_parser", 
		zeek::plugin::TCPExtractor_UrgentPointerExtractor::URG_parser::Instantiate));

	zeek::plugin::Configuration config;
	config.name = "TCPExtractor::UrgentPointerExtractor";
	config.description = "A plugin to extract the Urgent Pointer from TCP datagrams";
	config.version.major = 0;
	config.version.minor = 1;
	config.version.patch = 0;

	// EnableHook(zeek::plugin::HOOK_SETUP_ANALYZER_TREE, 0);

	return config;
	}

// void Plugin::HookSetupAnalyzerTree(zeek::Connection *conn)
// {
// 	// only take care of TCP packet
// 	if ( conn->ConnTransport() != TRANSPORT_TCP )
// 		return;

// 	zeek::analyzer::TransportLayerAnalyzer* root = 0;
// 	root = conn->GetRootAnalyzer();

// 	// create the packet analyzer
// 	URG_parser* urg_parser = new URG_parser(conn);

// 	// attach the packet analyzer to the analyzer tree
// 	((zeek::analyzer::tcp::TCP_Analyzer *) root)->AddChildPacketAnalyzer(urg_parser);
	
// 	urg_parser->Init();
// }