/*
 * kenotaphd - detect a presence of a network device
 * Copyright (C) 2016  CodeWard.org
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <pcap/pcap.h>
#include <poll.h>
#include <netdb.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <confuse.h>
#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include "kenotaphd.h"
#include "config.h"
#include "pidfile.h"
#include "pathname.h"
#include "nmsg_queue.h"
#include "session_data.h"
#include "hostport_parser.h"

static const unsigned int SELECT_TIMEOUT_MS = 700;
static const unsigned int ACCEPT_MAX = 32;
static const unsigned int LISTEN_QUEUE_LEN = 8;
static const unsigned int BPF_OPTIMIZE = 1;

struct option_data
{
	uint32_t accept_max;
	uint32_t ip_version;
	char port[PORT_MAX_LEN];
	char hostname[HOST_NAME_MAX];
	char pid_file[FILENAME_MAX];
	uint8_t has_pidfile;
	uint8_t prot_pidfile;
	uint8_t verbose;
	uint8_t tcp_event;
	uint8_t daemon;
};

static int main_loop;
static int exitno;
static struct option opt_long[] = {
	{ "", no_argument, NULL, '4' },
	{ "", no_argument, NULL, '6' },
	{ "hostname", required_argument, NULL, 't' },
	{ "daemon", no_argument, NULL, 'd' },
	{ "accept-max", required_argument, NULL, 'm' },
	{ "pid-file", required_argument, NULL, 'P' },
	{ "verbose", no_argument, NULL, 'V' },
	{ "help", no_argument, NULL, 'h' },
	{ "version", no_argument, NULL, 'v' },
	{ NULL, 0, NULL, 0 }
};

static void
kenotaphd_help (const char *p)
{
	fprintf (stdout, "Usage: %s [OPTIONS] -t HOSTNAME:PORT <config-file>\n\n"
					 "Options:\n"
					 "  -4                            resolve hostname to IPv4 address\n"
					 "  -6                            resolve hostname to IPv6 address\n"
					 "  -t, --hostname=HOSTNAME:PORT  bind socket to hostname and port\n"
					 "  -d, --daemon                  run as a daemon\n"
					 "  -m, --accept-max=NUM          accept maximum of NUM concurrent client connections\n"
					 "  -P, --pid-file=FILE           create a pid file FILE\n"
					 "  -V, --verbose                 increase verbosity\n"
					 "  -h, --help                    show usage information\n"
					 "  -v, --version                 show version information\n"
					 , p);
}

static void
kenotaphd_version (const char *p)
{
	fprintf (stdout, "%s %d.%d.%d\n%s\n", p, KENOTAPHD_VER_MAJOR, KENOTAPHD_VER_MINOR, KENOTAPHD_VER_PATCH, pcap_lib_version ());
}

static void
kenotaphd_sigdie (int signo)
{
	main_loop = 0;
	exitno = signo;
}


int
main (int argc, char *argv[])
{
	FILE *nstderr;
	struct pollfd *poll_fd;
	struct config_iface *confif_iter;
	struct config_dev *confdev_iter;
	struct session_data *pcap_session;
	struct config conf;
	struct nmsg_text nmsg_text;
	struct nmsg_node *nmsg_node;
	struct nmsg_queue nmsg_que;
	ssize_t nmsg_len;
	struct option_data opt;
	char *nmsg_buff;
	char conf_errbuff[CONF_ERRBUF_SIZE];
	char pcap_errbuff[PCAP_ERRBUF_SIZE];
	struct pathname path_config;
#ifdef DBG_AVG_LOOP_SPEED
	clock_t clock_start;
	double clock_avg;
#endif
	const u_char *pkt_data;
	struct pcap_pkthdr *pkt_header;
	struct bpf_program bpf_prog;
	time_t current_time;
	struct sigaction sa;
	struct addrinfo *host_addr, addr_hint;
	unsigned long filter_cnt;
	pid_t pid;
	bpf_u_int32 if_netaddr, if_netmask;
	int i, c, j, rval, syslog_flags, opt_index, opt_val, sock, poll_len, link_type, pipe_fd[2];

	sock = -1;
	poll_fd = NULL;
	pcap_session = NULL;
	host_addr = NULL;
	syslog_flags = LOG_PID | LOG_PERROR;
	nstderr = stderr;
	exitno = EXIT_SUCCESS;
#ifdef DBG_AVG_LOOP_SPEED
	clock_avg = 0;
#endif

	memset (&nmsg_que, 0, sizeof (struct nmsg_queue));
	memset (&path_config, 0, sizeof (struct pathname));
	memset (&conf, 0, sizeof (struct config));
	memset (&opt, 0, sizeof (struct option_data));
	memset (&addr_hint, 0, sizeof (struct addrinfo));

	opt.ip_version = AF_UNSPEC;
	opt.accept_max = ACCEPT_MAX;

	while ( (c = getopt_long (argc, argv, "46t:dm:P:Vhv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'd':
				opt.daemon = 1;
				break;

			case 't':
				rval = hostport_parse (optarg, opt.hostname, opt.port);

				if ( rval == -1 || strlen (opt.hostname) == 0 || strlen (opt.port) == 0 ){
					fprintf (nstderr, "%s: option '-t, --hostname' has invalid format (expects HOSTNAME:PORT)\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				opt.tcp_event = 1;
				break;

			case '4':
				opt.ip_version = AF_INET;
				break;

			case '6':
				opt.ip_version = AF_INET6;
				break;

			case 'm':
				rval = sscanf (optarg, "%u", &(opt.accept_max));

				if ( rval < 1 ){
					fprintf (nstderr, "%s: option '-m, --accept-max' has invalid format (expects a number)\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				if ( opt.accept_max == 0 ){
					fprintf (nstderr, "%s: option '-m, --accept-max' has invalid format (expects a number >0)\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
				break;

			case 'P':
				nmsg_len = strlen (optarg) + 1;

				if ( nmsg_len > sizeof (opt.pid_file) ){
					fprintf (nstderr, "%s: pid file name is too long\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}

				strncpy (opt.pid_file, optarg, nmsg_len);
				opt.pid_file[nmsg_len - 1] = '\0';

				opt.has_pidfile = 1;

				// Set pid file protection flag.
				// In case of an error when we have to jump to cleanup, make sure we do
				// not delete a file which was not created by this process.
				opt.prot_pidfile = 1;
				break;

			case 'V':
				opt.verbose = 1;
				break;

			case 'h':
				kenotaphd_help (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			case 'v':
				kenotaphd_version (argv[0]);
				exitno = EXIT_SUCCESS;
				goto cleanup;

			default:
				kenotaphd_help (argv[0]);
				exitno = EXIT_FAILURE;
				goto cleanup;
		}
	}

	// Check if there are some non-option arguments, these are treated as paths
	// to configuration files.
	if ( (argc - optind) == 0 ){
		fprintf (nstderr, "%s: configuration file not specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( opt.tcp_event == 0 ){
		fprintf (nstderr, "%s: daemon not binded to any hostname and port. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( opt.has_pidfile ){
		pid = pidfile_read (opt.pid_file);

		if ( pid == -1 ){
			fprintf (nstderr, "%s: invalid value inside of a pid file '%s'\n", argv[0], opt.pid_file);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Check pid
		if ( (pid > 0) && (pid != getpid ()) ){
			errno = 0;
			rval = kill (pid, 0);

			if ( rval == 0 ){
				fprintf (nstderr, "%s: an instance of a program is already running (pid: %u)\n", argv[0], pid);
				exitno = EXIT_FAILURE;
				goto cleanup;
			} else if ( (rval == -1) && (errno != ESRCH) ){
				fprintf (nstderr, "%s: cannot determine if a process exists: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		if ( pidfile_write (opt.pid_file) == -1 ){
			fprintf (nstderr, "%s: cannot create a pid file '%s': %s\n", argv[0], opt.pid_file, strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Unset pid file protection flag.
		opt.prot_pidfile = 0;
	}

	// Change working directory to match the dirname of the config file.
	rval = path_split (argv[optind], &path_config);

	if ( rval != 0 ){
		fprintf (nstderr, "%s: cannot split path to a configuration file.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = chdir (path_config.dir);

	if ( rval == -1 ){
		fprintf (nstderr, "%s: cannot change directory to '%s': %s\n", argv[0], path_config.dir, strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = config_load (&conf, path_config.base, &filter_cnt);

	switch ( rval ){
		case CFG_FILE_ERROR:
			fprintf (nstderr, "%s: cannot load a configuration file '%s': %s\n", argv[0], argv[optind], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;

		case CFG_PARSE_ERROR:
			exitno = EXIT_FAILURE;
			goto cleanup;
	}

	if ( filter_cnt == 0 ){
		fprintf (nstderr, "%s: no device rules defined, nothing to do...\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// No longer needed, free the resources
	path_free (&path_config);

	//
	// Daemonize the process if the flag was set
	//
	if ( opt.daemon ){

		if ( pipe (pipe_fd) == -1 ){
			fprintf (nstderr, "%s: cannot open pipe: %s\n", argv[0], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		pid = fork ();

		if ( pid == -1 ){
			fprintf (nstderr, "%s: cannot daemonize the process (fork failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Parent process...
		if ( pid > 0 ){
			close (pipe_fd[1]);

			nmsg_len = read (pipe_fd[0], conf_errbuff, sizeof (conf_errbuff));

			conf_errbuff[nmsg_len - 1] = '\0';

			if ( nmsg_len == -1 ){
				fprintf (nstderr, "%s: cannot read from pipe: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
			} else if ( nmsg_len == 0 ){
				exitno = EXIT_SUCCESS;
			} else {
				fprintf (nstderr, "%s\n", conf_errbuff);
				exitno = EXIT_FAILURE;
			}

			close (pipe_fd[0]);
			goto cleanup;

		} else {
			close (pipe_fd[0]);

			nstderr = fdopen (pipe_fd[1], "w");

			// XXX: leave 'stderr' as is...
			if ( nstderr == NULL ){
				fprintf (stderr, "%s: fdopen(3) failed: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}

		if ( setsid () == -1 ){
			fprintf (nstderr, "%s: cannot daemonize the process (setsid failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		umask (0);

		freopen ("/dev/null", "r", stdin);
		freopen ("/dev/null", "w", stdout);
		freopen ("/dev/null", "w", stderr);
		syslog_flags = LOG_PID;
	}

	//
	// Setup signal handler
	//
	sa.sa_handler = kenotaphd_sigdie;
	sigemptyset (&(sa.sa_mask));
	sa.sa_flags = 0;

	rval = 0;
	rval &= sigaction (SIGINT, &sa, NULL);
	rval &= sigaction (SIGQUIT, &sa, NULL);
	rval &= sigaction (SIGTERM, &sa, NULL);

	if ( rval != 0 ){
		fprintf (nstderr, "%s: cannot setup signal handler: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Setup addrinfo hints
	addr_hint.ai_family = opt.ip_version;
	addr_hint.ai_socktype = SOCK_STREAM;
	addr_hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

	rval = getaddrinfo (opt.hostname, opt.port, &addr_hint, &host_addr);

	if ( rval != 0 ){
		fprintf (nstderr, "%s: hostname resolve failed: %s\n", argv[0], gai_strerror (rval));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	sock = socket (host_addr->ai_family, host_addr->ai_socktype | SOCK_NONBLOCK, host_addr->ai_protocol);

	if ( sock == -1 ){
		freeaddrinfo (host_addr);
		fprintf (nstderr, "%s: cannot create a socket: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	opt_val = 1;

	if ( setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (opt_val)) == -1 ){
		freeaddrinfo (host_addr);
		fprintf (nstderr, "%s: cannot set socket options: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = bind (sock, (struct sockaddr*) host_addr->ai_addr, host_addr->ai_addrlen);

	if ( rval == -1 ){
		freeaddrinfo (host_addr);
		fprintf (nstderr, "%s: cannot bind to address: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = listen (sock, LISTEN_QUEUE_LEN);

	if ( rval == -1 ){
		freeaddrinfo (host_addr);
		fprintf (nstderr, "%s: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	freeaddrinfo (host_addr);

	pcap_session = (struct session_data*) calloc (filter_cnt, sizeof (struct session_data));

	if ( pcap_session == NULL ){
		fprintf (nstderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( confif_iter = conf.head; confif_iter != NULL; confif_iter = confif_iter->next ){

		if ( ! confif_iter->enabled )
			continue;

		for ( i = 0, confdev_iter = confif_iter->dev; confdev_iter != NULL; i++, confdev_iter = confdev_iter->next ){

			session_data_init (&(pcap_session[i]));

			pcap_session[i].timeout = confdev_iter->timeout;

			pcap_session[i].iface = strdup (confif_iter->name);

			if ( pcap_session[i].iface == NULL ){
				fprintf (nstderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_session[i].dev = strdup (confdev_iter->name);

			if ( pcap_session[i].dev == NULL ){
				fprintf (nstderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_session[i].handle = pcap_create (confif_iter->name, pcap_errbuff);

			if ( pcap_session[i].handle == NULL ){
				fprintf (nstderr, "%s: cannot use network interface: %s\n", argv[0], pcap_errbuff);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_set_rfmon (pcap_session[i].handle, (confif_iter->mode & CONF_IF_MONITOR));

			if ( rval != 0 ){
				fprintf (nstderr, "%s: interface '%s', cannot enable monitor mode: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_set_promisc (pcap_session[i].handle, (confif_iter->mode & CONF_IF_PROMISC));

			if ( rval != 0 ){
				fprintf (nstderr, "%s: interface '%s', cannot enable promiscuous mode: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_set_timeout (pcap_session[i].handle, SELECT_TIMEOUT_MS);

			if ( rval != 0 ){
				fprintf (nstderr, "%s: interface '%s', cannot set read timeout: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_setnonblock (pcap_session[i].handle, 1, pcap_errbuff);

			if ( rval == -1 ){
				fprintf (nstderr, "%s: interface '%s', cannot set nonblocking: %s\n", argv[0], confif_iter->name, pcap_errbuff);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_activate (pcap_session[i].handle);

			if ( rval != 0 ){
				fprintf (nstderr, "%s: interface '%s', cannot activate a packet capture: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			// Set link-layer type from configuration file.
			if ( confif_iter->link_type != NULL ){
				link_type = pcap_datalink_name_to_val (confif_iter->link_type);

				if ( link_type == -1 ){
					fprintf (nstderr, "%s: device rule '%s', unknown link-layer type '%s'\n", argv[0], confdev_iter->name, confif_iter->link_type);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
			} else {
				// If no link-layer type is specified in the configuration file,
				// use default value. At this point I am sticking with DLTs used by
				// wireshark on hardware I have available. Different values may
				// apply to different hardware/driver, therefore more research time
				// should be put into finding 'best' values.
				// More information: http://www.tcpdump.org/linktypes.html
				if ( confif_iter->mode & CONF_IF_MONITOR ){
					link_type = DLT_IEEE802_11_RADIO;
				} else {
					link_type = DLT_EN10MB;
				}
			}

			rval = pcap_set_datalink (pcap_session[i].handle, link_type);

			if ( rval == -1 ){
				fprintf (nstderr, "%s: interface '%s', cannot set data-link type: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			if_netmask = PCAP_NETMASK_UNKNOWN;

			// Obtain IP address of a network and the netmask.
			// This only makes sense if we are not capturing in monitor mode.
			if ( !(confif_iter->mode & CONF_IF_MONITOR) ){
				rval = pcap_lookupnet (confif_iter->name, &if_netaddr, &if_netmask, pcap_errbuff);

				if ( rval == -1 ){
					// This is a tricky part, if pcap_lookupnet returns an
					// error, should we die with error or simply set
					// PCAP_NETMASK_UNKNOWN and carry on, like we do now?  If
					// netmask is not known to pcap_compile, bpf's broadcast
					// directive will not work and pcap_compile will fail.
					// Also, does it makes sense to capture on an interface
					// without an IP address, if the interface is not in
					// monitor mode?
					if_netmask = PCAP_NETMASK_UNKNOWN;
				}
			}

			rval = pcap_compile (pcap_session[i].handle, &bpf_prog, confdev_iter->match, BPF_OPTIMIZE, if_netmask);

			if ( rval == -1 ){
				fprintf (nstderr, "%s: device rule '%s', cannot compile a packet filter: %s\n", argv[0], confdev_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_setfilter (pcap_session[i].handle, &bpf_prog);

			if ( rval == -1 ){
				pcap_freecode (&bpf_prog);
				fprintf (nstderr, "%s: interface '%s', cannot apply a packet filter: %s\n", argv[0], confif_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_freecode (&bpf_prog);

			pcap_session[i].fd = pcap_get_selectable_fd (pcap_session[i].handle);

			if ( pcap_session[i].fd == -1 ){
				fprintf (nstderr, "%s: interface '%s', cannot obtain a file descriptor\n", argv[0], confif_iter->name);
				exitno = EXIT_FAILURE;
				goto cleanup;
			}
		}
	}

	// We no longer need data stored in config structure. All neccessary data
	// were moved into session_data structure.
	config_unload (&conf);

	// TODO
	// Drop privileges here...
	//

	// Define a poll array length, the length includes space for all pcap fd +
	// listening socket + accept_max number of client sockets.
	poll_len = filter_cnt + 1 + opt.accept_max;

	poll_fd = (struct pollfd*) malloc (sizeof (struct pollfd) * poll_len);

	if ( poll_fd == NULL ){
		fprintf (nstderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Populate poll structure...
	for ( i = 0; i < poll_len; i++ ){
		// ... with pcap file descriptors...
		if ( i < filter_cnt )
			poll_fd[i].fd = pcap_session[i].fd;
		// ... listening socket...
		else if ( i == filter_cnt )
			poll_fd[i].fd = sock;
		// ... invalid file descriptors (will be ignored by poll(2)), in space reserved for client sockets...
		else
			poll_fd[i].fd = -1;

		poll_fd[i].events = POLLIN | POLLERR;
		poll_fd[i].revents = 0;
	}

	// If nstderr is an open pipe, close it, this will notify a parent process that we are done initializing.
	// All the code below MUST use syslog function to print data.
	if ( nstderr != stderr ){
		fclose (nstderr);
		nstderr = NULL;
	}

	openlog ("kenotaphd", syslog_flags, LOG_DAEMON);

	syslog (LOG_INFO, "kenotaph-daemon started (loaded device rules: %lu)", filter_cnt);

	if ( opt.tcp_event )
		syslog (LOG_INFO, "Event notifications available via %s:%s (ACCEPT_MAX: %u)", opt.hostname, opt.port, opt.accept_max);

	//
	// Main loop
	//
	main_loop = 1;

	while ( main_loop ){
		errno = 0;
		rval = poll (poll_fd, poll_len, SELECT_TIMEOUT_MS);

		if ( rval == -1 ){
			if ( errno == EINTR )
				continue;

			syslog (LOG_ERR, "poll(2) failed: %s", strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

#ifdef DBG_AVG_LOOP_SPEED
		clock_start = clock ();
#endif

		// Accept incoming connection
		if ( poll_fd[filter_cnt].revents & POLLIN ){
			struct sockaddr_in cli_addr;
			socklen_t cli_addrlen;
			int sock_new;

			cli_addrlen = sizeof (cli_addr);

			sock_new = accept (sock, (struct sockaddr*) &cli_addr, &cli_addrlen);

			if ( sock_new == -1 ){
				syslog (LOG_ERR, "cannot accept new connection: %s", strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			// Find unused place in the poll array
			for ( j = (filter_cnt + 1); j < poll_len; j++ ){
				if ( poll_fd[j].fd == -1 ){
					poll_fd[j].fd = sock_new;
					sock_new = -1;
					break;
				}
			}

			if ( sock_new != -1 ){
				if ( opt.verbose )
					syslog (LOG_INFO, "Client refused: too many concurrent connections");
				close (sock_new);
			} else {
				if ( opt.verbose ){
					char cliaddr_str[INET6_ADDRSTRLEN];

					if ( inet_ntop (cli_addr.sin_family, &(cli_addr.sin_addr), cliaddr_str, sizeof (cliaddr_str)) == NULL ){
						syslog (LOG_ERR, "cannot convert client address: %s", strerror (errno));
						exitno = EXIT_FAILURE;
						goto cleanup;
					}

					syslog (LOG_INFO, "Client %s:%hu connected...", cliaddr_str, ntohs (cli_addr.sin_port));
				}
			}
		}

		// Take care of incoming client data.  At this point only shutdown and
		// close is handled, no other input is expected from the clients.
		for ( i = (filter_cnt + 1); i < poll_len; i++ ){
			if ( poll_fd[i].revents & POLLIN ){
				char nok[128];

				errno = 0;
				rval = recv (poll_fd[i].fd, &nok, sizeof (nok), MSG_DONTWAIT);

				if ( rval <= 0 && (errno != EAGAIN && errno != EWOULDBLOCK) ){
					if ( opt.verbose )
						syslog (LOG_INFO, "Client disconnected...");
					close (poll_fd[i].fd);
					poll_fd[i].fd = -1;
				}
			}
		}

		time (&current_time);

		// Handle changes on pcap file descriptors
		for ( i = 0; i < filter_cnt; i++ ){
			const char *evt_str;

			// Handle incoming packet
			if ( (poll_fd[i].revents & POLLIN) || (poll_fd[i].revents & POLLERR) ){
				rval = pcap_next_ex (pcap_session[i].handle, &pkt_header, &pkt_data);

				if ( rval == 1 ){
					if ( pcap_session[i].evt.ts == 0 )
						pcap_session[i].evt.type = SE_BEG;

					pcap_session[i].evt.ts = pkt_header->ts.tv_sec;
				} else if ( rval < 0 ){
					pcap_session[i].evt.type = SE_ERR;
				}
			}

			if ( (pcap_session[i].evt.ts > 0)
					&& (difftime (current_time, pcap_session[i].evt.ts) >= pcap_session[i].timeout) ){
				pcap_session[i].evt.type = SE_END;
			}

			switch ( pcap_session[i].evt.type ){
				case SE_NUL:
					// There was no change on this file descriptor, skip to
					// another one. 'continue' may seem a bit confusing here,
					// but it applies to a loop above. Not sure how other
					// compilers will behave (other than gcc).
					continue;

				case SE_BEG:
					evt_str = "BEG";
					pcap_session[i].evt.type = SE_NUL;
					break;

				case SE_END:
					evt_str = "END";
					pcap_session[i].evt.type = SE_NUL;
					pcap_session[i].evt.ts = 0;
					break;

				case SE_ERR:
					evt_str = "ERR";
					pcap_session[i].evt.type = SE_NUL;
					pcap_session[i].evt.ts = 0;
					break;

				default:
					// Undefined state... What to do, other than die?
					syslog (LOG_ERR, "undefined event type");
					exitno = EXIT_FAILURE;
					goto cleanup;
			}

			strncpy (nmsg_text.iface, pcap_session[i].iface, NMSG_IF_MAXLEN);
			nmsg_text.iface[NMSG_IF_MAXLEN] = '\0';

			strncpy (nmsg_text.id, pcap_session[i].dev, NMSG_ID_MAXLEN);
			nmsg_text.id[NMSG_ID_MAXLEN] = '\0';

			strncpy (nmsg_text.type, evt_str, NMSG_TYPE_MAXLEN);
			nmsg_text.type[NMSG_TYPE_MAXLEN] = '\0';

			nmsg_node = nmsg_node_new (&nmsg_text);

			if ( nmsg_node == NULL ){
				syslog (LOG_ERR, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			nmsg_queue_push (&nmsg_que, nmsg_node);

			if ( opt.verbose )
				syslog (LOG_INFO, "%s", nmsg_node->msg);
		}

		nmsg_len = nmsg_queue_serialize (&nmsg_que, &nmsg_buff);

		if ( nmsg_len == -1 ){
			syslog (LOG_ERR, "%s: cannot serialize enqued data: %s\n", argv[0], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		if ( nmsg_len > 0 ){
			nmsg_queue_free (&nmsg_que);

			// Send notification messsages here...
			for ( i = (filter_cnt + 1); i < poll_len; i++ ){
				if ( poll_fd[i].fd == -1 )
					continue;

				errno = 0;
				rval = send (poll_fd[i].fd, nmsg_buff, (size_t) nmsg_len, MSG_NOSIGNAL | MSG_DONTWAIT);

				if ( rval == -1 && (errno != EAGAIN && errno != EWOULDBLOCK) ){
					syslog (LOG_WARNING, "failed to send notification: %s", strerror (errno));
					close (poll_fd[i].fd);
					poll_fd[i].fd = -1;
				}
			}

			free (nmsg_buff);
		}

#ifdef DBG_AVG_LOOP_SPEED
		clock_avg = (clock_avg + (clock () - clock_start)) / 2;

		syslog (LOG_DEBUG, "Average loop speed: %lf", (double) (clock_avg / CLOCKS_PER_SEC));
#endif
	}

	syslog (LOG_INFO, "kenotaph-daemon shutdown (signal %u)", exitno);

cleanup:
	closelog ();

	if ( nstderr != NULL )
		fclose (nstderr);

	if ( pcap_session != NULL ){
		for ( i = 0; i < filter_cnt; i++ )
			session_data_free (&(pcap_session[i]));
		free (pcap_session);
	}

	nmsg_queue_free (&nmsg_que);

	if ( poll_fd != NULL ){
		for ( i = (filter_cnt + 1); i < poll_len; i++ ){
			if ( poll_fd[i].fd == -1 )
				continue;

			close (poll_fd[i].fd);
		}
		free (poll_fd);
	}

	if ( sock != -1 )
		close (sock);

	config_unload (&conf);

	path_free (&path_config);

	if ( opt.has_pidfile && !opt.prot_pidfile )
		unlink (opt.pid_file);

	return exitno;
}

