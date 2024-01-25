#ifndef AUX_PLUGINS_HEADER_URGENTPOINTER_H
#define AUX_PLUGINS_HEADER_URGENTPOINTER_H

#include "analyzer/protocol/tcp/TCP.h"
#include <zeek/analyzer/Analyzer.h>
#include "urgentpointerextractor.bif.h"
#include <vector>
#include <sstream>
#include "Event.h"

namespace zeek::plugin { namespace TCPExtractor_UrgentPointerExtractor {

class URG_parser : public analyzer::tcp::TCP_ApplicationAnalyzer {
public:
	URG_parser(Connection* conn) : TCP_ApplicationAnalyzer ("URG_parser", conn), 
		_conn(conn) {}
	virtual ~URG_parser() {}

	virtual void Init() {TCP_ApplicationAnalyzer::Init();}
	virtual void Done() {TCP_ApplicationAnalyzer::Done();}

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new URG_parser(conn); }
protected:
	// when there is a packet get the URG_flag and URG_ptr
	virtual void DeliverPacket(int len, const u_char* data, bool is_orig,
                                uint64_t seq, const IP_Hdr* ip, int caplen);

private:
	Connection *_conn;

};

} } 

#endif
