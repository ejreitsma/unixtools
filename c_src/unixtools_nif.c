// Copyright (c) 2017 Erik Reitsma <development@ernovation.com>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <fcntl.h>
#include <unistd.h>
#include "erl_nif.h"

static ERL_NIF_TERM term_from_result(ErlNifEnv* env,
				     int res);

static ERL_NIF_TERM nif_getsockname(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int fd, res;
  struct sockaddr *addr;
  socklen_t addrlen;
  ErlNifBinary addrBinary;
  
  if (argc!=1)
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }
  
  addrlen = 2048;
  addr = enif_alloc(addrlen);
  
  res = getsockname(fd, 
		    addr, &addrlen);
  
  if (res<0) 
    {
      enif_free(addr);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      enif_alloc_binary(addrlen, &addrBinary);
      memcpy(addrBinary.data, addr, addrlen);
      enif_free(addr);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_binary(env, &addrBinary));
    }

}

static ERL_NIF_TERM nif_socket(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int domain, type, res, protocol;

  if (argc!=3) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  if (!enif_get_int(env, argv[0], &domain)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[1], &type)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[2], &protocol)) {
    return enif_make_badarg(env);
  }
  
  res = socket(domain, type, htons((uint16_t)protocol));

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_setsockopt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int sockfd, level, optname, res;
  ErlNifBinary optBinary;

  if (argc!=4) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  if (!enif_get_int(env, argv[0], &sockfd)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[1], &level)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[2], &optname)) {
    return enif_make_badarg(env);
  }
  if (!enif_inspect_binary(env, argv[3], &optBinary)) {
    return enif_make_badarg(env);
  }
  
  res = setsockopt(sockfd, level, optname, 
		   optBinary.data, optBinary.size);

  enif_release_binary(&optBinary);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_getsockopt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  int sockfd, level, optname, res;
  ErlNifBinary optBin;
  void *optval;
  socklen_t optlen;

  if (argc!=3) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  if (!enif_get_int(env, argv[0], &sockfd)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[1], &level)) {
    return enif_make_badarg(env);
  }
  if (!enif_get_int(env, argv[2], &optname)) {
    return enif_make_badarg(env);
  }

  optlen = 2048;
  optval = enif_alloc(optlen);

  res = getsockopt(sockfd, level, optname, 
		   optval, &optlen);

  if (res<0) 
    {
      enif_free(optval);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      enif_alloc_binary(optlen, &optBin);
      memcpy(optBin.data, optval, optlen);
      enif_free(optval);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_binary(env, &optBin));
    }
}

static ERL_NIF_TERM nif_if_nametoindex(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
  unsigned res;
  ErlNifBinary name;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  if (!enif_inspect_binary(env, argv[0], &name)) {
    return enif_make_badarg(env);
  }

  res = if_nametoindex((const char*)name.data);
  
  enif_release_binary(&name);

  return 
    enif_make_int(env, res);
}

static ERL_NIF_TERM nif_bind(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  ErlNifBinary addrBinary;
  int res;

  if (argc!=2) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &addrBinary)) {
    return enif_make_badarg(env);
  }

  res = bind(fd, (const struct sockaddr*)(addrBinary.data), addrBinary.size);

  enif_release_binary(&addrBinary);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_connect(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  ErlNifBinary addrBinary;
  int res;

  if (argc!=2) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &addrBinary)) {
    return enif_make_badarg(env);
  }

  res = connect(fd, (const struct sockaddr*)(addrBinary.data), addrBinary.size);

  enif_release_binary(&addrBinary);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_sendto(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd, flags;
  ErlNifBinary addrBinary, dataBinary;
  int res;

  if (argc!=4) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[1], &dataBinary)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[2], &flags)) {
    return enif_make_badarg(env);
  }

  if (!enif_inspect_binary(env, argv[3], &addrBinary)) {
    return enif_make_badarg(env);
  }

  res = sendto(fd, dataBinary.data, dataBinary.size,
	       flags,
	       (const struct sockaddr*)(addrBinary.data), addrBinary.size);

  enif_release_binary(&addrBinary);
  enif_release_binary(&dataBinary);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_open(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int flags;
  ErlNifBinary nameBinary;
  char *name;
  int res;

  if (argc!=2) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_inspect_binary(env, argv[0], &nameBinary)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &flags)) {
    return enif_make_badarg(env);
  }

  // copy the name into a string, with a terminating zero
  name = enif_alloc(nameBinary.size+1);
  memcpy(name, nameBinary.data, nameBinary.size);
  name[nameBinary.size] = 0;

  res = open(name, flags);

  enif_release_binary(&nameBinary);

  enif_free(name);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_close(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  res = close(fd);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_setuid(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int uid;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &uid)) {
    return enif_make_badarg(env);
  }

  res = setuid(uid);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_setgid(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int gid;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &gid)) {
    return enif_make_badarg(env);
  }

  res = setgid(gid);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_seteuid(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int uid;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &uid)) {
    return enif_make_badarg(env);
  }

  res = seteuid(uid);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_setegid(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int gid;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &gid)) {
    return enif_make_badarg(env);
  }

  res = setegid(gid);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_getuid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int uid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  uid = getuid();

  return enif_make_int(env, uid);
}

static ERL_NIF_TERM nif_getgid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int gid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  gid = getgid();

  return enif_make_int(env, gid);
}

#ifdef __USE_GNU

static ERL_NIF_TERM nif_getresuid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  unsigned int res, ruid, euid, suid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  res = getresuid(&ruid, &euid, &suid);

  if (res<0) 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_tuple3(env,
					       enif_make_int(env, ruid),
					       enif_make_int(env, euid),
					       enif_make_int(env, suid)));
    }

}

static ERL_NIF_TERM nif_getresgid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  unsigned int res, rgid, egid, sgid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  res = getresgid(&rgid, &egid, &sgid);

  if (res<0) 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_tuple3(env,
					       enif_make_int(env, rgid),
					       enif_make_int(env, egid),
					       enif_make_int(env, sgid)));
    }

}

#endif /* Use GNU */

static ERL_NIF_TERM nif_geteuid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int uid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  uid = geteuid();

  return enif_make_int(env, uid);
}

static ERL_NIF_TERM nif_getegid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int gid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  gid = getegid();

  return enif_make_int(env, gid);
}

static ERL_NIF_TERM nif_getpid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int pid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  pid = getpid();

  return enif_make_int(env, pid);
}

static ERL_NIF_TERM nif_getppid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int ppid;

  if (argc!=0) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }

  ppid = getppid();

  return enif_make_int(env, ppid);
}

static ERL_NIF_TERM nif_getpgid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int pgid;
  int pid;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &pid)) {
    return enif_make_badarg(env);
  }


  pgid = getpgid(pid);

  return enif_make_int(env, pgid);
}

static ERL_NIF_TERM nif_getsid(ErlNifEnv* env,
			       int argc,
			       const ERL_NIF_TERM argv[])
{
  int sid;
  int pid;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &pid)) {
    return enif_make_badarg(env);
  }


  sid = getsid(pid);

  return enif_make_int(env, sid);
}

static ERL_NIF_TERM nif_listen(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  int backlog;
  int res;

  if (argc!=2) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &backlog)) {
    return enif_make_badarg(env);
  }

  res = listen(fd, backlog);

  return term_from_result(env, res);
}


static ERL_NIF_TERM nif_accept(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  int res;
  struct sockaddr *addr;
  socklen_t addrlen;
  ErlNifBinary *addrBin;

  addrBin = NULL;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  addrlen = 1024;
  addr = enif_alloc(addrlen);

  res = accept(fd, addr, &addrlen);

  if (res<0) 
    {
      enif_free(addr);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      enif_alloc_binary(addrlen, addrBin);
      memcpy(addrBin->data, addr, addrlen);
      enif_free(addr);
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_binary(env, addrBin));
    }

}

static ERL_NIF_TERM nif_fcntl_void(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int fd;
  int command;
  int res;

  if (argc!=2) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &command)) {
    return enif_make_badarg(env);
  }

  res = fcntl(fd, command);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_fcntl_long(ErlNifEnv* env,
				   int argc,
				   const ERL_NIF_TERM argv[])
{
  int fd;
  int command;
  long arg;
  int res;

  if (argc!=3) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &fd)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_int(env, argv[1], &command)) {
    return enif_make_badarg(env);
  }

  if (!enif_get_long(env, argv[2], &arg)) {
    return enif_make_badarg(env);
  }

  res = fcntl(fd, command, arg);

  return term_from_result(env, res);
}

static ERL_NIF_TERM nif_nice(ErlNifEnv* env,
			     int argc,
			     const ERL_NIF_TERM argv[])
{
  int inc;
  int res;

  if (argc!=1) 
    {
      // wrong number of args
      return enif_make_badarg(env);
    }
  
  if (!enif_get_int(env, argv[0], &inc)) {
    return enif_make_badarg(env);
  }

  res = nice(inc);

  return term_from_result(env, res);
}


static ERL_NIF_TERM term_from_result(ErlNifEnv* env,
				     int res)
{  
  if (res<0) 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "error"),
			      enif_make_atom(env, strerror(errno)));
    }
  else 
    {
      return enif_make_tuple2(env,
			      enif_make_atom(env, "ok"),
			      enif_make_int(env, res));
    }
}

static ErlNifFunc nif_funcs[] = {
  {"nif_open", 2, nif_open},
  {"nif_close", 1, nif_close},
  {"nif_socket", 3, nif_socket},
  {"nif_getsockname", 1, nif_getsockname},
  {"nif_setsockopt", 4, nif_setsockopt},
  {"nif_getsockopt", 3, nif_getsockopt},
  {"nif_if_nametoindex", 1, nif_if_nametoindex},
  {"nif_bind", 2, nif_bind},
  {"nif_connect", 2, nif_connect},
  {"nif_sendto", 4, nif_sendto},
  {"nif_accept", 1, nif_accept},
  {"nif_listen", 2, nif_listen},
  {"nif_fcntl_void", 2, nif_fcntl_void},
  {"nif_fcntl_long", 3, nif_fcntl_long},
  {"nif_setuid", 1, nif_setuid},
  {"nif_setgid", 1, nif_setgid},
  {"nif_seteuid", 1, nif_seteuid},
  {"nif_setegid", 1, nif_setegid},
  {"nif_getuid", 0, nif_getuid},
  {"nif_getgid", 0, nif_getgid},
#ifdef __USE_GNU
  {"nif_getresuid", 0, nif_getresuid},
  {"nif_getresgid", 0, nif_getresgid},
#endif /* Use GNU */
  {"nif_geteuid", 0, nif_geteuid},
  {"nif_getegid", 0, nif_getegid}, 
  {"nif_nice", 1, nif_nice},
  {"nif_getpid", 0, nif_getpid},
  {"nif_getppid", 0, nif_getppid},
  {"nif_getpgid", 1, nif_getpgid},
  {"nif_getsid", 1, nif_getsid},

};

ERL_NIF_INIT(unixtools, nif_funcs, NULL, NULL, NULL, NULL)

