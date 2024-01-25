#include "Event.h"              

#include "URG_parser.h"
#include "Conn.h"
#include "urgentpointerextractor.bif.h"
#include "zeek/Val.h"

using namespace zeek::plugin::TCPExtractor_UrgentPointerExtractor;

void URG_parser::DeliverPacket(int len, const u_char* data, bool is_orig,
                                uint64_t seq, const IP_Hdr* ip, int caplen)
{
  	//Gets Header and delivers packet to app analyzer

	//first check if packet has data
  	if ((data == NULL) || (ip == NULL)) 
	{
#ifdef DEBUG_H
		printf("data or ip header is null");
#endif
		return;
	}
	Analyzer::DeliverPacket(len, data, is_orig, seq, ip, caplen);

	if (ip != 0) {  
		//if IP part exists, get tcp part
		// by extracting payload from IP part
		const struct tcphdr* tp = (const struct tcphdr*) ip->Payload();
#ifdef DEBUG_H
		printf("URG : %u, Pointer : %u\n", tp->urg, tp->urg_ptr);
#endif

	zeek::EventHandlerPtr ev;
	ev = UrgentPointerExtractor::URG_feature_event;
		// build the conn_id
		// RecordVal* id_val = new RecordVal(zeek::id::conn_id);
		// id_val->Assign(0, new AddrVal(_conn->OrigAddr()));
		// // id_val->Assign(1, new PortVal(ntohs(_conn->OrigPort()), TRANSPORT_TCP));
		// id_val->Assign(1, new PortVal(ntohs(_conn->OrigPort())));
		// id_val->Assign(2, new AddrVal(_conn->RespAddr()));
		// // id_val->Assign(3, new PortVal(ntohs(_conn->RespPort()), TRANSPORT_TCP));
		// id_val->Assign(3, new PortVal(ntohs(_conn->RespPort()));

		// val_list *vl = new val_list;
		// vl->append(new StringVal((_conn->GetUID()).Base62("C")));   // pass the UID
		// vl->append(id_val);                                         // conn_ID
        // vl->append(new Val((is_orig) ? 0 : 1, TYPE_ENUM));          // Direction
		// vl->append(new Val(tp->urg, TYPE_COUNT));                   // URG_flag
		// vl->append(new Val(ntohs(tp->urg_ptr), TYPE_COUNT));        // URG_ptr
		// Connection::EnqueueEvent(UrgentPointerExtractor::URG_feature_event, vl);
		// Connection::EnqueueEvent(UrgentPointerExtractor::URG_feature_event, zeek:Args{
		Analyzer::EnqueueConnEvent(ev, zeek::Args{
			ConnVal(),
			zeek::val_mgr->Count(tp->urg),
			zeek::val_mgr->Count(ntohs(tp->urg_ptr))
		});
	}
}

