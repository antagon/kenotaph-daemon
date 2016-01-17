/*
 * Copyright (c) 2016, CodeWard.org
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include <time.h>
#include <pcap.h>
#include <poll.h>
#include <netdb.h>
#include <libconfig.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <getopt.h>
#include <syslog.h>
#include <unistd.h>

#include "kenotaphd.h"
#include "config.h"
#include "pathname.h"
#include "session_data.h"
#include "hostport_parser.h"

static const unsigned int SELECT_TIMEOUT_MS = 700;
static const unsigned int ACCEPT_MAX = 32;
static const unsigned int LISTEN_QUEUE_LEN = 8;

struct option_data
{
	uint32_t accept_max;
	uint32_t ip_version;
	char port[PORT_MAX_LEN];
	char hostname[HOST_NAME_MAX];
	uint8_t verbose;
	uint8_t tcp_event;
	uint8_t daemon;
};

static int main_loop;
static int exitno;

static void
kenotaphd_help (const char *p)
{
	fprintf (stdout, "Usage: %s [OPTIONS] <FILE>\n\n"
					 "Options:\n"
					 "  -4                        bind to IPv4 address\n"
					 "  -6                        bind to IPv6 address\n"
					 "  -t, --hostname=HOST:PORT  bind to address/hostname and port\n"
					 "  -d, --daemon              run as a daemon\n"
					 "  -m, --accept-max=NUM      accept maximum of NUM concurrent client connections\n"
					 "  -V, --verbose             increase verbosity\n"
					 "  -h, --help                show this usage information\n"
					 "  -v, --version             show version information\n"
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
	struct pollfd *poll_fd;
	struct config kenotaphd_conf;
	struct config_filter *filter_iter;
	struct session_data *pcap_session;
	struct option_data opt;
	char conf_errbuff[CONF_ERRBUF_SIZE];
	char pcap_errbuff[PCAP_ERRBUF_SIZE];
	struct pathname path_config;
#ifdef DBG_AVG_LOOP_SPEED
	clock_t clock_start;
	double clock_avg;
#endif
	struct sigaction sa;
	struct addrinfo *host_addr, addr_hint;
	struct option opt_long[] = {
		{ "", no_argument, NULL, '4' },
		{ "", no_argument, NULL, '6' },
		{ "hostname", required_argument, NULL, 't' },
		{ "daemon", no_argument, NULL, 'd' },
		{ "accept-max", required_argument, NULL, 'm' },
		{ "verbose", no_argument, NULL, 'V' },
		{ "help", no_argument, NULL, 'h' },
		{ "version", no_argument, NULL, 'v' },
		{ NULL, 0, NULL, 0 }
	};
	pid_t pid;
	int i, c, j, rval, syslog_flags, opt_index, opt_val, filter_cnt, sock, poll_len;

	sock = -1;
	poll_fd = NULL;
	pcap_session = NULL;
	exitno = EXIT_SUCCESS;
	syslog_flags = LOG_PID | LOG_PERROR;
#ifdef DBG_AVG_LOOP_SPEED
	clock_avg = 0;
#endif

	memset (&opt, 0, sizeof (struct option_data));

	opt.ip_version = AF_UNSPEC;
	opt.accept_max = ACCEPT_MAX;

	memset (&path_config, 0, sizeof (struct pathname));
	memset (&kenotaphd_conf, 0, sizeof (struct config));

	while ( (c = getopt_long (argc, argv, "46t:dm:Vhv", opt_long, &opt_index)) != -1 ){
		switch ( c ){
			case 'd':
				opt.daemon = 1;
				break;

			case 't':
				rval = hostport_parse (optarg, opt.hostname, opt.port);

				if ( rval == -1 || strlen (opt.hostname) == 0 || strlen (opt.port) == 0 ){
					fprintf (stderr, "%s: invalid hostname format (expects HOSTNAME:PORT)\n", argv[0]);
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
				sscanf (optarg, "%u", &(opt.accept_max));

				if ( opt.accept_max == 0 ){
					fprintf (stderr, "%s: invalid number for maximum connections\n", argv[0]);
					exitno = EXIT_FAILURE;
					goto cleanup;
				}
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
		fprintf (stderr, "%s: configuration file not specified. Use '--help' to see usage information.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	if ( opt.tcp_event == 0 ){
		fprintf (stderr, "%s: daemon not binded to any hostname and port. Use '--help' to see usage information.\n", argv[0]);
		kenotaphd_help (argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// Change working directory to match the dirname of the config file.
	rval = path_split (argv[optind], &path_config);

	if ( rval != 0 ){
		fprintf (stderr, "%s: cannot split path to a configuration file.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = chdir (path_config.dir);

	if ( rval == -1 ){
		fprintf (stderr, "%s: cannot set working directory to '%s': %s\n", argv[0], path_config.dir, strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	//
	// Load configuration file
	//
	filter_cnt = config_load (&kenotaphd_conf, path_config.base, conf_errbuff);

	if ( filter_cnt == -1 ){
		fprintf (stderr, "%s: cannot load a configuration file '%s': %s\n", argv[0], argv[optind], conf_errbuff);
		exitno = EXIT_FAILURE;
		goto cleanup;
	} else if ( filter_cnt == 0 ){
		fprintf (stderr, "%s: nothing to do, no filters defined.\n", argv[0]);
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	// No longer needed, free the resources
	path_free (&path_config);

	// Define a poll array length, the length includes space for all pcap fd +
	// listening socket + accept_max number of client sockets.
	poll_len = filter_cnt + 1 + opt.accept_max;
	host_addr = NULL;

	memset (&addr_hint, 0, sizeof (struct addrinfo));

	// Setup addrinfo hints
	addr_hint.ai_family = opt.ip_version;
	addr_hint.ai_socktype = SOCK_STREAM;
	addr_hint.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

	rval = getaddrinfo (opt.hostname, opt.port, &addr_hint, &host_addr);

	if ( rval != 0 ){
		fprintf (stderr, "%s: hostname resolve failed: %s\n", argv[0], gai_strerror (rval));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	sock = socket (host_addr->ai_family, host_addr->ai_socktype | SOCK_NONBLOCK, host_addr->ai_protocol);

	if ( sock == -1 ){
		freeaddrinfo (host_addr);
		fprintf (stderr, "%s: cannot create socket: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	opt_val = 1;

	if ( setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof (opt_val)) == -1 ){
		freeaddrinfo (host_addr);
		fprintf (stderr, "%s: cannot set socket options: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = bind (sock, (struct sockaddr*) host_addr->ai_addr, host_addr->ai_addrlen);

	if ( rval == -1 ){
		freeaddrinfo (host_addr);
		fprintf (stderr, "%s: cannot bind to address: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	rval = listen (sock, LISTEN_QUEUE_LEN);

	if ( rval == -1 ){
		freeaddrinfo (host_addr);
		fprintf (stderr, "%s: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	freeaddrinfo (host_addr);

	pcap_session = (struct session_data*) calloc (filter_cnt, sizeof (struct session_data));

	if ( pcap_session == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	for ( i = 0, filter_iter = kenotaphd_conf.head; filter_iter != NULL; i++, filter_iter = filter_iter->next ){
		int link_type;

		session_data_init (&(pcap_session[i]));

		pcap_session[i].timeout = filter_iter->session_timeout;

		pcap_session[i].filter_name = strdup (filter_iter->name);

		if ( pcap_session[i].filter_name == NULL ){
			fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		pcap_session[i].handle = pcap_create (filter_iter->iface, pcap_errbuff);

		if ( pcap_session[i].handle == NULL ){
			fprintf (stderr, "%s: cannot start packet capture: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_rfmon (pcap_session[i].handle, filter_iter->rfmon);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable monitor mode on interface '%s': %s\n", argv[0], filter_iter->iface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_promisc (pcap_session[i].handle, !(filter_iter->rfmon));

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot enable promiscuous mode on interface '%s'\n", argv[0], filter_iter->iface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_set_timeout (pcap_session[i].handle, SELECT_TIMEOUT_MS);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot set read timeout on interface '%s': %s\n", argv[0], filter_iter->iface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_setnonblock (pcap_session[i].handle, 1, pcap_errbuff);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set nonblock mode on packet capture resource: %s\n", argv[0], pcap_errbuff);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		rval = pcap_activate (pcap_session[i].handle);

		if ( rval != 0 ){
			fprintf (stderr, "%s: cannot activate packet capture on interface '%s': %s\n", argv[0], filter_iter->iface, pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		// Set link-layer type from configuration file.
		if ( filter_iter->link_type != NULL ){
			link_type = pcap_datalink_name_to_val (filter_iter->link_type);

			if ( link_type == -1 ){
				fprintf (stderr, "%s: cannot convert link-layer type '%s': unknown identificator\n", argv[0], filter_iter->link_type);
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
			if ( filter_iter->rfmon ){
				link_type = DLT_IEEE802_11_RADIO;
			} else {
				link_type = DLT_EN10MB;
			}
		}

		rval = pcap_set_datalink (pcap_session[i].handle, link_type);

		if ( rval == -1 ){
			fprintf (stderr, "%s: cannot set data-link type: %s\n", argv[0], pcap_geterr (pcap_session[i].handle));
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		if ( filter_iter->match != NULL ){
			struct bpf_program bpf_prog;

			rval = pcap_compile (pcap_session[i].handle, &bpf_prog, filter_iter->match, 0, PCAP_NETMASK_UNKNOWN);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot compile the filter '%s' match rule: %s\n", argv[0], filter_iter->name, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			rval = pcap_setfilter (pcap_session[i].handle, &bpf_prog);

			if ( rval == -1 ){
				fprintf (stderr, "%s: cannot apply the filter '%s' on interface '%s': %s\n", argv[0], filter_iter->name, filter_iter->iface, pcap_geterr (pcap_session[i].handle));
				exitno = EXIT_FAILURE;
				goto cleanup;
			}

			pcap_freecode (&bpf_prog);
		}

		pcap_session[i].fd = pcap_get_selectable_fd (pcap_session[i].handle);

		if ( pcap_session[i].fd == -1 ){
			fprintf (stderr, "%s: cannot obtain file descriptor for packet capture interface '%s'\n", argv[0], filter_iter->iface);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}
	}

	// We no longer need data stored in config structure. All neccessary data
	// were moved into session_data structure.
	config_unload (&kenotaphd_conf);

	poll_fd = (struct pollfd*) malloc (sizeof (struct pollfd) * poll_len);

	if ( poll_fd == NULL ){
		fprintf (stderr, "%s: cannot allocate memory: %s\n", argv[0], strerror (errno));
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

	sa.sa_handler = SIG_IGN;
	sigemptyset (&(sa.sa_mask));
	sa.sa_flags = 0;

	rval &= sigaction (SIGCHLD, &sa, NULL);

	if ( rval != 0 ){
		fprintf (stderr, "%s: cannot setup signal handler: %s\n", argv[0], strerror (errno));
		exitno = EXIT_FAILURE;
		goto cleanup;
	}

	//
	// Daemonize the process if the flag was set
	//
	if ( opt.daemon == 1 ){
		pid = fork ();

		if ( pid > 0 ){
			exitno = EXIT_SUCCESS;
			goto cleanup;
		} else if ( pid == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (fork failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		if ( setsid () == -1 ){
			fprintf (stderr, "%s: cannot daemonize the process (setsid failed).\n", argv[0]);
			exitno = EXIT_FAILURE;
			goto cleanup;
		}

		umask (0);

		freopen ("/dev/null", "r", stdin);
		freopen ("/dev/null", "w", stdout);
		freopen ("/dev/null", "w", stderr);
		syslog_flags = LOG_PID;
	}

	openlog ("kenotaphd", syslog_flags, LOG_DAEMON);

	syslog (LOG_INFO, "kenotaph-daemon started (loaded filters: %u)", filter_cnt);

	if ( opt.tcp_event )
		syslog (LOG_INFO, "Event notifications available via %s:%s (ACCEPT_MAX: %u)", opt.hostname, opt.port, opt.accept_max);

	//
	// Main loop
	//
	main_loop = 1;

	while ( main_loop ){
		const u_char *pkt_data;
		struct pcap_pkthdr *pkt_header;
		time_t current_time;

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
			int sock_new;

			sock_new = accept (sock, NULL, NULL);

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
				if ( opt.verbose )
					syslog (LOG_INFO, "Client connected...");
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
			char msg[CONF_FILTER_NAME_MAXLEN + 5];
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

			if ( opt.verbose )
				syslog (LOG_INFO, "%s:%s", pcap_session[i].filter_name, evt_str);

			// Store a notification message in buffer
			snprintf (msg, sizeof (msg), "%s:%s", pcap_session[i].filter_name, evt_str);

			// Send notification messsages here...
			for ( i = (filter_cnt + 1); i < poll_len; i++ ){
				if ( poll_fd[i].fd == -1 )
					continue;

				errno = 0;
				rval = send (poll_fd[i].fd, msg, strlen (msg) + 1, MSG_NOSIGNAL | MSG_DONTWAIT);

				if ( rval == -1 && (errno != EAGAIN && errno != EWOULDBLOCK) ){
					syslog (LOG_WARNING, "failed to send notification: %s", strerror (errno));
					close (poll_fd[i].fd);
					poll_fd[i].fd = -1;
				}
			}
		}

#ifdef DBG_AVG_LOOP_SPEED
		clock_avg = (clock_avg + (clock () - clock_start)) / 2;

		syslog (LOG_DEBUG, "Average loop speed: %lf", (double) (clock_avg / CLOCKS_PER_SEC));
#endif
	}

	syslog (LOG_INFO, "kenotaph-daemon shutdown (signal %u)", exitno);

cleanup:
	closelog ();

	if ( pcap_session != NULL ){
		for ( i = 0; i < filter_cnt; i++ )
			session_data_free (&(pcap_session[i]));
		free (pcap_session);
	}

	if ( poll_fd != NULL )
		free (poll_fd);

	if ( sock != -1 )
		close (sock);

	config_unload (&kenotaphd_conf);

	path_free (&path_config);

	return exitno;
}

