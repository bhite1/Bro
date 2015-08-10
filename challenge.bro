global source_ports: table[port] of time;
global first_contact: time;

### Unix Command(s)
# This command reads the first field in a tab-delimited file
## awk -F '\t' '{ print $1 }' conn.log | tail
# This command enables horizontal scrolling
## less -S conn.log
# Shows fields avaialable
## grep ^#fields conn.log | tr '\t' '\n'
# Similar to the awk above but for Bro
## bro-cut -d ts id.orig_h id.orig_p id.resp_h id.resp_p proto < conn.log | head
###

event connection_established(c: connection)
      {                 
      #print c;
	  if (c$id$resp_p == 4445/tcp)
	  	first_contact = c$start_time;
      }

event new_connection(c: connection)
      {                 
      #print c;
	  if (c$id$orig_h == 10.10.10.70 && c$id$resp_p == 4445/tcp)
	  #print fmt("New Connection => orig: %s %s resp: %s %s time: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, c$start_time);
	  	{
		if (c$id$orig_p !in source_ports)
			source_ports[c$id$orig_p] = c$start_time;
		}
      }

event bro_done()
	{
	local ptime: set[time];
	local sports: vector of port;
	local stime: vector of time;
	local inc: int = 0;

	for (p in source_ports)
		{
		sports[inc] = p;
		stime[inc] = source_ports[p];
		inc+=1;
		}
	sort(stime);
	sort(sports);
	for (j in stime)
		{
		print fmt("Delta Time: %s", stime[j+1] - stime[j]);
		}

	print strftime("Successful connection to 4445/tcp at %Y/%m/%d %H:%M:%S", first_contact);
	}