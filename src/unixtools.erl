%% Copyright (c) 2017 Erik Reitsma <development@ernovation.nl>

-module(unixtools).

-export([open/2, close/1, 
	 bind/2, connect/2, listen/2, socket/3, accept/1, 
	 getsockname/1,
	 setsockopt/4, getsockopt/3,
	 if_nametoindex/1,
	 sendto/4,
	 fcntl/2, fcntl/3,
	 setuid/1, setgid/1, seteuid/1, setegid/1,
	 getuid/0, getgid/0, 
	 getresuid/0, getresgid/0, 
	 geteuid/0, getegid/0,
	 nice/1, getpid/0, getppid/0, getpgid/1, getsid/1
	]).

-on_load(init/0).


init() ->
     ok = erlang:load_nif(code:priv_dir(unixtools)++"/unixtools", 0).

open(Name, Flags) when is_list(Name) ->
    open(list_to_binary(Name), Flags);
open(Name, Flags) when is_binary(Name) ->
    nif_open(Name, unixtools_types:encode_file_option_list(Flags)).

nif_open(_Name, _Flags) ->
    exit(nif_library_not_loaded).

close(Fd) when is_integer(Fd) ->
    nif_close(Fd).

nif_close(_Fd) ->
    exit(nif_library_not_loaded).

fcntl(Fd, Command) when is_integer(Fd), is_integer(Command) ->
    nif_fcntl_void(Fd, Command).

nif_fcntl_void(_Fd, _Command) ->
    exit(nif_library_not_loaded).

fcntl(Fd, Command, Arg) when is_integer(Fd), is_integer(Command), is_integer(Arg) ->
    nif_fcntl_long(Fd, Command, Arg).

nif_fcntl_long(_Fd, _Command, _Arg) ->
    exit(nif_library_not_loaded).

bind(Fd, Address) when is_integer(Fd), is_binary(Address) ->
    nif_bind(Fd, Address).

nif_bind(_Fd, _Address) ->
    exit(nif_library_not_loaded).

connect(Fd, Address) when is_integer(Fd), is_binary(Address) ->
    nif_connect(Fd, Address).

nif_connect(_Fd, _Address) ->
    exit(nif_library_not_loaded).

accept(Fd) when is_integer(Fd) ->
    nif_accept(Fd).

nif_accept(_Fd) ->
    exit(nif_library_not_loaded).

sendto(Fd, Data, Flags, Addr) when is_integer(Fd), 
				   is_binary(Data),
				   is_binary(Addr) ->
    nif_sendto(Fd, Data, unixtools_types:encode_msgflag_list(Flags), Addr).

nif_sendto(_Fd, _Data, _Flags, _Addr) ->
    exit(nif_library_not_loaded).

listen(Fd, Backlog) when is_integer(Fd), is_integer(Backlog) ->
    nif_listen(Fd, Backlog).

nif_listen(_Fd, _Backlog) ->
    exit(nif_library_not_loaded).

socket(Domain, Type, Protocol) when is_atom(Domain) ->
    socket(unixtools_types:encode_address_family(Domain), Type, Protocol);
socket(Domain, Type, Protocol) ->
    nif_socket(Domain, unixtools_types:encode_sock_list(Type), Protocol).
   
nif_socket(_Domain, _Type, _Protocol) ->
    exit(nif_library_not_loaded).

getsockname(Fd) ->
    nif_getsockname(Fd).

nif_getsockname(_Fd) ->
    exit(nif_library_not_loaded).

setsockopt(Fd, Level, OptName, OptVal) when is_atom(OptName) ->
    setsockopt(Fd, Level, unixtools_types:encode_so(OptName), OptVal);
setsockopt(Fd, Level, OptName, OptVal) when is_list(OptVal) ->
    setsockopt(Fd, Level, OptName, list_to_binary(OptVal));
setsockopt(Fd, Level, OptName, OptVal) ->
    nif_setsockopt(Fd, Level, OptName, OptVal).

nif_setsockopt(_Fd, _Level, _OptName, _OptVal) ->
    exit(nif_library_not_loaded).
    
getsockopt(Fd, Level, OptName) ->
    nif_getsockopt(Fd, Level, OptName).

nif_getsockopt(_Fd, _Level, _OptName) ->
    exit(nif_library_not_loaded).
    
if_nametoindex(Name) when is_list(Name) ->
    nif_if_nametoindex(list_to_binary(Name));
if_nametoindex(Name) ->
    nif_if_nametoindex(Name).

nif_if_nametoindex(_Name) ->
    exit(nif_library_not_loaded).
    
setuid(UID) when is_integer(UID) ->
    nif_setuid(UID).

nif_setuid(_UID) ->
    exit(nif_library_not_loaded).
    
setgid(GID) when is_integer(GID) ->
    nif_setgid(GID).

nif_setgid(_GID) ->
    exit(nif_library_not_loaded).
    
seteuid(UID) when is_integer(UID) ->
    nif_seteuid(UID).

nif_seteuid(_UID) ->
    exit(nif_library_not_loaded).
    
setegid(GID) when is_integer(GID) ->
    nif_setegid(GID).

nif_setegid(_GID) ->
    exit(nif_library_not_loaded).
    
getuid() ->
    nif_getuid().

nif_getuid() ->
    exit(nif_library_not_loaded).
    
getgid() ->
    nif_getgid().

nif_getgid() ->
    exit(nif_library_not_loaded).
    
geteuid() ->
    nif_geteuid().

nif_geteuid() ->
    exit(nif_library_not_loaded).
    
getegid() ->
    nif_getegid().

nif_getegid() ->
    exit(nif_library_not_loaded).

getresuid() ->
    nif_getresuid().

nif_getresuid() ->
    exit(nif_library_not_loaded).
    
getresgid() ->
    nif_getresgid().

nif_getresgid() ->
    exit(nif_library_not_loaded).
    

nice(Inc) when is_integer(Inc) ->
    nif_nice(Inc).

nif_nice(_Inc) ->
    exit(nif_library_not_loaded).
    
getpid() ->
    nif_getpid().

nif_getpid() ->
    exit(nif_library_not_loaded).

getppid() ->
    nif_getppid().

nif_getppid() ->
    exit(nif_library_not_loaded).

getpgid(Pid) ->
    nif_getpgid(Pid).

nif_getpgid(_Pid) ->
    exit(nif_library_not_loaded).

getsid(Pid) ->
    nif_getsid(Pid).

nif_getsid(_Pid) ->
    exit(nif_library_not_loaded).



