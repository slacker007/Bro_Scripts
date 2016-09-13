@load base/protocols/dns


event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count){
	print fmt ("Query: %s", query);
}	
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr){
        print fmt ("ANS: %s", ans);
	print fmt ("ADDRESS: %s", a);
        }

event dns_TXT_reply(c: connection, msg: dns_msg, ans: dns_answer, strs: string_vec){
	print fmt ("REPLY: %s", ans);
	}

event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
        {
        print ans;
	print a;
        }

event dns_A6_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr) &priority=5
        {
        print ans;
        }

event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
        {
        print ans;
        }

event dns_CNAME_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
        {
        print ans;
	print name;
        }

event dns_MX_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string, preference: count)
        {
        print ans;
        }
event dns_NS_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
        {
        print ans;
        }

event dns_PTR_reply(c: connection, msg: dns_msg, ans: dns_answer, name: string) &priority=5
        {
        print  ans;
	print name;
        }

event dns_SOA_reply(c: connection, msg: dns_msg, ans: dns_answer, soa: dns_soa) &priority=5
        {
        print ans;
	print soa;
        }

event dns_WKS_reply(c: connection, msg: dns_msg, ans: dns_answer) &priority=5
        {
        print ans;
        }

event dns_SRV_reply(c: connection, msg: dns_msg, ans: dns_answer, target: string, priority: count, weight: count, p: count) &priority=5
        {
        print ans;
        }
