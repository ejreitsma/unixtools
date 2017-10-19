%% Copyright (c) 2017 Erik Reitsma <development@ernovation.nl>

-record(sockaddr_ll,
	{family,
	 protocol,
	 ifindex,
	 hatype,
	 pkttype,
	 addr}).
