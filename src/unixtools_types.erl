%% Copyright (c) 2017 Erik Reitsma <development@ernovation.nl>

-module(unixtools_types).

-include("unixtools_types.hrl").

-export([encode_sock_list/1, 
	 encode_file_option_list/1,
	 encode_msgflag_list/1]).

-export([encode_sockaddr_ll/1]).

-compile({parse_transform, codec_transform}).
    
-codec({file_option,
	[
	 {8#0, rdonly},
	 {8#1, wronly},
	 {8#2, rdwr},
	 {8#100, creat},	%% not fcntl 
	 {8#200, excl},	%% not fcntl 
	 {8#400, noctty},	%% not fcntl 
	 {8#1000, trunc},	%% not fcntl 
	 {8#2000, append},
	 {8#4000, nonblock},
	 %%{ndelay  ,nonblock},
	 {8#10000, sync},
	 %%{fsync		, sync},
	 {8#20000, async},
	 {8#40000, direct},	%% direct disk access.	
	 {8#200000, directory},	%% must be a directory.	 
	 {8#400000, nofollow},	%% do not follow links.	 
	 {8#1000000, noatime},%% do not set atime. 
	 {8#2000000, cloexec}]}).%% set close_on_exec. 

encode_file_option_list(L) ->
    encode_option_list(L, fun(A) -> encode_file_option(A) end).

-codec({msgflag, 
	[{16#01, oob},
	 {16#02, peek},
	 {16#04, dontroute},
	 {16#08, ctrunc},
	 {16#10, proxy},
	 {16#20, trunc},
	 {16#40, dontwait},
	 {16#80, eor},
	 {16#100, waitall},
	 {16#200, fin},
	 {16#400, syn},
	 {16#800, confirm},
	 {16#1000, rst},
	 {16#2000, errqueue},
	 {16#4000, nosignal},
	 {16#8000, more},
	 {16#10000, waitforone},
	 {16#40000000, cmsg_cloexec}]}).

encode_msgflag_list(L) ->
    encode_option_list(L, fun(A) -> encode_msgflag(A) end).

-codec({address_family,
	[{0,unspec}, %% Unspecified.  
	 {1,local}, %% Local to host (pipes and file-domain},  
	 %%{1,UNIX,?LOCAL}, %% POSIX name for LOCAL.  
	 %%{1,FILE,?LOCAL}, %% Another non-standard name for LOCAL.  
	 {2,inet,2}, %% IP protocol family.  
	 {3,ax25}, %% Amateur Radio AX.25.  
	 {4,ipx}, %% Novell Internet Protocol.  
	 {5,appletalk}, %% Appletalk DDP.  
	 {6,netrom}, %% Amateur radio NetROM.  
	 {7,bridge}, %% Multiprotocol bridge.  
	 {8,atmpvc}, %% ATM PVCs.  
	 {9,x25}, %% Reserved for X.25 project.  
	 {10,inet6}, %% IP version 6.  
	 {11,rose}, %% Amateur Radio X.25 PLP.  
	 {12,decnet}, %% Reserved for DECnet project.  
	 {13,netbeui}, %% Reserved for 802.2LLC project.  
	 {14,security}, %% Security callback pseudo AF.  
	 {15,key}, %% KEY key management API.  
	 {16,netlink},
	 {17,packet}, %% Packet family.  
	 {18,ash}, %% Ash.  
	 {19,econet}, %% Acorn Econet.  
	 {20,atmsvc}, %% ATM SVCs.  
	 {21,rds}, %% RDS sockets.  
	 {22,sna}, %% Linux SNA Project 
	 {23,irda}, %% IRDA sockets.  
	 {24,pppox}, %% PPPoX sockets.  
	 {25,wanpipe}, %% Wanpipe API sockets.  
	 {26,llc}, %% Linux LLC.  
	 {29,can}, %% Controller Area Network.  
	 {30,tipc}, %% TIPC sockets.  
	 {31,bluetooth}, %% Bluetooth sockets.  
	 {32,iucv}, %% IUCV sockets.  
	 {33,rxrpc}, %% RxRPC sockets.  
	 {34,isdn}, %% mISDN sockets.  
	 {35,phonet}, %% Phonet sockets.  
	 {36,ieee802154}, %% IEEE 802.15.4 sockets.  
	 {37,max}]}). %% For now..  

	     
-codec({sock,
	[{1,stream},
	 {2,dgram},
	 {3,raw},
	 {4,rdm},
	 {5,seqpacket},
	 {6,dccp},
	 {10,packet},
	 {8#2000000,cloexec},
	 {8#4000,nonblock}]}).

-codec({fcntl,
	[{0, dupfd},
	 {1, getfd},
	 {2, setfd},
	 {3, getfl},
	 {4, setfl},
	 {5, getlk},
	 {6, setlk},
	 {7, setlkw},
	 {8, setown},
	 {9, getown}]}).

-codec({protocol_family,
	[{0,unspec}, %% Unspecified.  
	 {1,local}, %% Local to host (pipes and file-domain).  
	 %%{1,UNIX,?LOCAL). %% POSIX name for LOCAL.  
	 %%{1,FILE,?LOCAL). %% Another non-standard name for LOCAL.  
	 {2,inet,2}, %% IP protocol family.  
	 {3,ax25}, %% Amateur Radio AX.25.  
	 {4,ipx}, %% Novell Internet Protocol.  
	 {5,appletalk}, %% Appletalk DDP.  
	 {6,netrom}, %% Amateur radio NetROM.  
	 {7,bridge}, %% Multiprotocol bridge.  
	 {8,atmpvc}, %% ATM PVCs.  
	 {9,x25}, %% Reserved for X.25 project.  
	 {10,inet6}, %% IP version 6.  
	 {11,rose}, %% Amateur Radio X.25 PLP.  
	 {12,decnet}, %% Reserved for DECnet project.  
	 {13,netbeui}, %% Reserved for 802.2LLC project.  
	 {14,security}, %% Security callback pseudo AF.  
	 {15,key}, %% KEY key management API.  
	 {16,netlink},
	 {17,packet}, %% Packet family.  
	 {18,ash}, %% Ash.  
	 {19,econet}, %% Acorn Econet.  
	 {20,atmsvc}, %% ATM SVCs.  
	 {21,rds}, %% RDS sockets.  
	 {22,sna}, %% Linux SNA Project 
	 {23,irda}, %% IRDA sockets.  
	 {24,pppox}, %% PPPoX sockets.  
	 {25,wanpipe}, %% Wanpipe API sockets.  
	 {26,llc}, %% Linux LLC.  
	 {29,can}, %% Controller Area Network.  
	 {30,tipc}, %% TIPC sockets.  
	 {31,bluetooth}, %% Bluetooth sockets.  
	 {32,iucv}, %% IUCV sockets.  
	 {33,rxrpc}, %% RxRPC sockets.  
	 {34,isdn}, %% mISDN sockets.  
	 {35,phonet}, %% Phonet sockets.  
	 {36,ieee802154}, %% IEEE 802.15.4 sockets.  
	 {37,max}]}). %% For now..  

encode_option_list([], _F) ->
    0;
encode_option_list([H|T], F) when is_atom(H) ->
    F(H) bor encode_option_list(T, F);
encode_option_list([H|T], F) ->
    H bor encode_option_list(T, F);
encode_option_list(A, F) when is_atom(A) ->
    F(A);
encode_option_list(I, _F) when is_integer(I) ->
    I.

encode_sock_list(L) ->
    encode_option_list(L, fun(A) -> encode_sock(A) end).

encode_sockaddr_ll(A) ->
    <<(encode_address_family(A#sockaddr_ll.family)):16/native-integer,
      (encode_eth_p(A#sockaddr_ll.protocol)):16/big-integer,
      (A#sockaddr_ll.ifindex):32/native-integer,
      (encode_arphrd(A#sockaddr_ll.hatype)):16/native-integer,
      (encode_packet_type(A#sockaddr_ll.pkttype)),
      (size(A#sockaddr_ll.addr)),
      (fill_binary(A#sockaddr_ll.addr, 8, 0))/binary>>.

fill_binary(B, Size, _Fill) when size(B) == Size ->
    B;
fill_binary(B, Size, _Fill) when size(B) > Size->
    <<Res:Size/binary, _/binary>> = B,
    Res;
fill_binary(B, Size, Fill) ->
    fill_binary(<<B/binary, Fill>>, Size, Fill).

-codec({so,
	[{1, debug},
	 {2, reuseaddr},
	 {3, type},
	 {4, error},
	 {5, dontroute},
	 {6, broadcast},
	 {7, sndbuf},
	 {8, rcvbuf},
	 {32, sndbufforce},
	 {33, rcvbufforce},
	 {9, keepalive},
	 {10, oobinline},
	 {11, no_check},
	 {12, priority},
	 {13, linger},
	 {14, bsdcompat},
	 {15, reuseport},
	 {16, passcred},
	 {17, peercred},
	 {18, rcvlowat},
	 {19, sndlowat},
	 {20, rcvtimeo},
	 {21, sndtimeo},
	 {22, security_authentication},
	 {23, security_encryption_transport},
	 {24, security_encryption_network},
	 {25, bindtodevice},
	 {26, attach_filter},
	 {27, detach_filter},
	 {28, peername},
	 {29, timestamp},
	 {30, acceptconn},
	 {31, peersec},
	 {34, passsec},
	 {35, timestampns},
	 {36, mark},
	 {37, timestamping},
	 {38, protocol},
	 {39, domain},
	 {40, rxq_ovfl}]
       }).

-codec({arphrd,
	[
	 {0, netrom     }, %% from KA9Q: NET/ROM pseudo	
	 {1, ether 	}, %% Ethernet 10Mbps		
	 {2, eether	}, %% Experimental Ethernet	
	 {3, ax25	}, %% AX.25 Level 2		
	 {4, pronet	}, %% PROnet token ring		
	 {5, chaos	}, %% Chaosnet			
	 {6, ieee802	}, %% IEEE 802.2 Ethernet/TR/TB	
	 {7, arcnet	}, %% ARCnet			
	 {8, appletlk	}, %% APPLEtalk			
	 {15, dlci	}, %% Frame Relay DLCI		
	 {19, atm	}, %% ATM 				
	 {23, metricom	}, %% Metricom STRIP (new IANA id)	
	 {24, ieee1394	}, %% IEEE 1394 IPv4 - RFC 2734	
	 {27, eui64	}, %% EUI-64                       
	 {32, infiniband }, %% InfiniBand			
	 {256, slip	},
	 {257, cslip	},
	 {258, slip6	},
	 {259, cslip6	},
	 {260, rsrvd	}, %% Notional KISS type 		
	 {264, adapt	},
	 {270, rose	},
	 {271, x25	}, %% CCITT X.25			
	 {272, hwx25	}, %% Boards with X.25 in firmware	
	 {280, can	}, %% Controller Area Network      
	 {512, ppp	},
	 {513, cisco	}, %% Cisco HDLC	 		
	 {516, lapb	}, %% LAPB				
	 {517, ddcmp    }, %% Digital's DDCMP protocol     
	 {518, rawhdlc	}, %% Raw HDLC			
	 
	 {768, tunnel	}, %% IPIP tunnel			
	 {769, tunnel6	}, %% IP6IP6 tunnel       		
	 {770, frad	}, %% Frame Relay Access Device    
	 {771, skip	}, %% SKIP vif			
	 {772, loopback	}, %% Loopback device		
	 {773, localtlk  }, %% Localtalk device		
	 {774, fddi	}, %% Fiber Distributed Data Interface 
	 {775, bif       }, %% AP1000 BIF                   
	 {776, sit	}, %% sit0 device - IPv6-in-IPv4	
	 {777, ipddp	}, %% IP over DDP tunneller	
	 {778, ipgre	}, %% GRE over IP			
	 {779, pimreg	}, %% PIMSM register interface	
	 {780, hippi	}, %% High Performance Parallel Interface 
	 {781, ash	}, %% Nexus 64Mbps Ash		
	 {782, econet	}, %% Acorn Econet			
	 {783, irda 	}, %% Linux-IrDA			
	 %% ARP works differently on different FC media .. so  
	 {784, fcpp	}, %% Point to point fibrechannel	
	 {785, fcal	}, %% Fibrechannel arbitrated loop 
	 {786, fcpl	}, %% Fibrechannel public loop	
	 {787, fcfabric	}, %% Fibrechannel fabric		
	 %% 787->799 reserved for fibrechannel media types 
	 {800, ieee802_tr }, %% Magic type ident for TR	
	 {801, ieee80211 }, %% IEEE 802.11			
	 {802, ieee80211_prism }, %% IEEE 802.11 + Prism2 header  
	 {803, ieee80211_radiotap }, %% IEEE 802.11 + radiotap header 
	 {804, ieee802154	  },
	 
	 {820, phonet	}, %% PhoNet media type		
	 {821, phonet_pipe}, %% PhoNet pipe header		
	 {822, caif	}, %% CAIF media type		
	 
	 {16#ffff, void	  }, %% Void type, nothing is known 
	 {16#fffe, none	  } %% zero header length 
	]}).

-codec({packet_type,
	[{0, host},
	 {1, broadcast},
	 {2, multicast},
	 {3, otherhost},
	 {4, outgoing},
	 {5, loopback},
	 {6, fastroute}]}).

-codec({eth_p,
	[
	 {16#0060, loop},		%% Ethernet Loopback packet	
	 {16#0200, pup},		%% Xerox PUP packet		
	 {16#0201, pupat},		%% Xerox PUP Addr Trans packet	
	 {16#0800, ip},		%% Internet Protocol packet	
	 {16#0805, x25},		%% CCITT X.25			
	 {16#0806, arp},		%% Address Resolution packet	
	 {16#08FF, bpq},		%% G8BPQ AX.25 Ethernet Packet	[ NOT AN OFFICIALLY REGISTERED ID ] 
	 {16#0a00, ieeepup},	%% Xerox IEEE802.3 PUP packet 
	 {16#0a01, ieeepupat},	%% Xerox IEEE802.3 PUP Addr Trans packet 
	 {16#6000, dec},          %% DEC Assigned proto           
	 {16#6001, dna_dl},        %% DEC DNA Dump/Load            
	 {16#6002, dna_rc},        %% DEC DNA Remote Console       
	 {16#6003, dna_rt},        %% DEC DNA Routing              
	 {16#6004, lat},          %% DEC LAT                      
	 {16#6005, diag},          %% DEC Diagnostics              
	 {16#6006, cust},          %% DEC Customer use             
	 {16#6007, sca},          %% DEC Systems Comms Arch       
	 {16#6558, teb},		%% Trans Ether Bridging		
	 {16#8035, rarp},		%% Reverse Addr Res packet	
	 {16#809B, atalk},		%% Appletalk DDP		
	 {16#80F3, aarp},		%% Appletalk AARP		
	 {16#8100, '8021Q'},       %% 802.1Q VLAN Extended Header  
	 {16#8137, ipx},		%% IPX over DIX			
	 {16#86DD, ipv6},		%% IPv6 over bluebook		
	 {16#8808, pause},		%% IEEE Pause frames. See 802.3 31B 
	 {16#8809, slow},		%% Slow Protocol. See 802.3ad 43B 
	 {16#883E, wccp},		%% Web-cache coordination protocol
	 {16#8863, ppp_disc},	%% PPPoE discovery messages     
	 {16#8864, ppp_ses},	%% PPPoE session messages	
	 {16#8847, mpls_uc},	%% MPLS Unicast traffic		
	 {16#8848, mpls_mc},	%% MPLS Multicast traffic	
	 {16#884c, atmmpoa},	%% MultiProtocol Over ATM	
	 {16#886c, link_ctl},	%% HPNA, wlan link local tunnel 
	 {16#8884, atmfate},	%% Frame-based ATM Transport over Ethernet
	 %%
	 {16#888E, pae},		%% Port Access Entity (IEEE 802.1X) 
	 {16#88A2, aoe},		%% ATA over Ethernet		
	 {16#88CA, tipc},		%% TIPC 			
	 {16#88F7, '1588'},		%% IEEE 1588 Timesync 
	 {16#8906, fcoe},		%% Fibre Channel over Ethernet  
	 {16#8914, fip},		%% FCoE Initialization Protocol 
	 {16#DADA, edsa},		%% Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] 
	 
	 %%
	 %%	Non DIX types. Won't clash for 1500 types.
	 %%
	 
	 {16#0001, '802_3'},		%% Dummy type for 802.3 frames  
	 {16#0002, ax25},		%% Dummy protocol id for AX.25  
	 {16#0003, all},		%% Every packet (be careful!!!) 
	 {16#0004, '802_2'},		%% 802.2 frames 		
	 {16#0005, snap},		%% Internal only		
	 {16#0006, ddcmp},          %% DEC DDCMP: Internal only     
	 {16#0007, wan_ppp},          %% Dummy type for WAN PPP fram
	 {16#0008, ppp_mp},          %% Dummy type for PPP MP frames 
	 {16#0009, localtalk},		%% Localtalk pseudo type 	
	 {16#000C, can},		%% Controller Area Network      
	 {16#0010, ppptalk},		%% Dummy type for Atalk over 
	 {16#0011, tr_802_2},		%% 802.2 frames 		
	 {16#0015, mobitex},		%% Mobitex (kaz@cafe.net)	
	 {16#0016, control},		%% Card specific control frames 
	 {16#0017, irda},		%% Linux-IrDA			
	 {16#0018, econet},		%% Acorn Econet			
	 {16#0019, hdlc},		%% HDLC frames			
	 {16#001A, arcnet},		%% 1A for ArcNet :-)            
	 {16#001B, dsa},		%% Distributed Switch Arch.	
	 {16#001C, trailer},		%% Trailer switch tagging	
	 {16#00F5, phonet},		%% Nokia Phonet frames          
	 {16#00F6, ieee802154},		%% IEEE802.15.4 frame		
	 {16#00F7, caif}		%% ST-Ericsson CAIF protocol	
	]}).
