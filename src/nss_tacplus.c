#include "libtac/libtac.h"

#include <arpa/inet.h>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <grp.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <nss.h>
#include <pthread.h>
#include <pwd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define TACPLUS_CONF_FILE "/etc/nss_tacplus.conf"
#define CONFIG_BUFSZ 1024

static pthread_once_t G_tacplus_initialized = PTHREAD_ONCE_INIT;
static time_t G_tacplus_started = -1;
static uint32_t G_tacplus_cycles = 0;
static char G_tacplus_confbuf[CONFIG_BUFSZ];
static struct tacplus_conf_st
{
    enum nss_status status;
    int errnum;

    time_t mtime;

    struct addrinfo *servers;
    struct addrinfo *lastsrv;

    char *secret;
    uint32_t timeout;
    uint8_t debug;
    char *service;
    char *protocol;
} G_tacplus_conf;

static const char CONFKEY_SERVER[]   = "server";
static const char CONFKEY_SECRET[]   = "secret";
static const char CONFKEY_TIMEOUT[]  = "timeout";
static const char CONFKEY_DEBUG[]    = "debug";
static const char CONFKEY_SERVICE[]  = "service";
static const char CONFKEY_PROTOCOL[] = "protocol";

static const char NO_PASSWD[] = "x";

/**
 * Safely convert a base-10 string into an unsigned long. This function
 * doesn't alter `out' if the conversion fails.
 *
 * \param[in]  str the string source used for the conversion
 * \param[out] out an output variable for the converted value
 * \retval 0 on success, else -1
 */
static int8_t _safe_convert_ulong(const char *str, unsigned long *out)
{
    int8_t result = 0;
    unsigned long val = 0;
    char *endptr = NULL;

    assert(NULL != out);

    errno = 0;
    val = strtoul(str, &endptr, 10);

    if (   (ERANGE == errno && (ULONG_MAX == val || 0 == val))
        || (0 != errno && 0 == val))
    {
        char errtext[256];
        int errnum = errno;

        strerror_r(errnum, errtext, sizeof(errtext));
        if (G_tacplus_conf.debug)
        {
            syslog(LOG_ERR, "nss_tacplus: strtoul got error: errno=%d, errtext=`%s'", errnum, errtext);
        }
        result = -1;
    }

    if (str != endptr)
    {
        *out = val;
    }
    else
    {
        result = -1;
    }

    return result;
}

/**
 * Parses the configuration for this module. The format is simple:
 *   server <ip[:port]>[,ip[:port]]...[ip[:port]]
 *   secret <secret>              (used by all servers)
 *   timeout <seconds>            (used by all servers)
 *   service <TACACS+ service>    (defaults to linuxlogin)
 *   protocol <TACACS+ protocol>  (defaults to ssh)
 *   debug                        (enable debug)
 *
 * \param[in] buffer a buffer than can be used to store string values
 * \param[in] buflen the length of the `buffer'
 * \retval enum nss_status NSS_STATUS_SUCCESS on succes, NSS_STATUS_UNAVAIL
 *                         if configuration file cannot be read,
 *                         NSS_STATUS_TRYAGAIN on potentially recoverable
 *                         conditions
 */
static enum nss_status _parse_config(char *buffer, size_t buflen)
{
    enum nss_status status = NSS_STATUS_SUCCESS;
    FILE *fp = NULL;
    struct stat conf_stat;
    char *offset = buffer;
    ptrdiff_t bufleft = buflen - (offset - buffer);
    char fbuf[CONFIG_BUFSZ];

    errno = 0;
    fp = fopen(TACPLUS_CONF_FILE, "r");
    if (NULL == fp)
    {
        char errtext[256];
        int errnum = errno;

        strerror_r(errnum, errtext, sizeof(errtext));
        syslog(LOG_ERR, "nss_tacplus: could not open config file %s", TACPLUS_CONF_FILE);

        errno = errnum;
        return NSS_STATUS_UNAVAIL;
    }

    memset(&conf_stat, 0, sizeof(conf_stat));
    if (0 == fstat(fileno(fp), &conf_stat))
    {
        G_tacplus_conf.mtime = conf_stat.st_mtime;
    }

    // ensure that we have a timeout, by default
    tac_readtimeout_enable = 1;

    // read a line from the file
    while (NULL != fgets(fbuf, sizeof(fbuf), fp))
    {
        char *key = NULL;
        char *val = NULL;
        char *endval = NULL;
        size_t len = 0;
        char* temp;

        // ignore empty lines and comments
        if ('#' == *fbuf || '\n' == *fbuf)
        {
            continue;
        }

        // everything points to the beginning of the line
        key = val = fbuf;

        // the keyword is everything at the beginning of the line
        while ('\0' != *val && !isspace(*val))
        {
            ++val;
        }

        // keyword with no value? silently ignore
        if ('#' == *val || '\0' == *val)
        {
            continue;
        }

        // null terminate keyword
        *(val++) = '\0';

        // move past remaining whitespace
        while (isspace(*val))
        {
            ++val;
        }

        len = strlen(val) - 1;
        while (isspace(val[len]))
        {
            --len;
        }
        val[++len] = '\0';
        endval = (val + len);

        // if val start with quote then find endquote
        if (*val == '"')
        {
            val++;
            if ((temp = strchr(val, '"')) == NULL)
                continue;
            *temp = 0;
            endval = temp;
        }
        else
        {
            if ((temp = strchr(val, '#')) != NULL)
            {
                *temp = 0;
                endval = temp;
            }
            if ((temp = strchr(val, ' ')) != NULL)
            {
                *temp = 0;
                endval = temp;
            }
        }

        if (0 == strncmp(key, CONFKEY_SERVER, sizeof(CONFKEY_SERVER)))
        {
            char *srv = val;
            struct addrinfo hints;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_STREAM;

            while (endval > val)
            {
                struct addrinfo *servers = NULL;
                char *port = NULL;

                while ('\0' != *srv && ',' != *srv && ':' != *srv)
                {
                    ++srv;
                }
                if (':' == *srv)
                {
                    *srv = '\0';
                    port = ++srv;
                    while ('\0' != *srv && ',' != *srv)
                    {
                        ++srv;
                    }
                }

                *srv = '\0';

                if (0 == getaddrinfo(val, port ? port : "49", &hints, &servers))
                {
                    assert(NULL != servers);

                    if (NULL == G_tacplus_conf.lastsrv)
                    {
                        assert(NULL == G_tacplus_conf.servers);
                        G_tacplus_conf.lastsrv =
                            G_tacplus_conf.servers = servers;
                    }
                    else
                    {
                        assert(NULL != G_tacplus_conf.servers);
                        G_tacplus_conf.lastsrv->ai_next = servers;
                    }

                    // iterate our linked-list to the end
                    while (NULL != G_tacplus_conf.lastsrv->ai_next)
                    {
                        G_tacplus_conf.lastsrv =
                            G_tacplus_conf.lastsrv->ai_next;
                    }
                }

                val = ++srv;
            }
        }
        else if (0 == strncmp(key, CONFKEY_SECRET, sizeof(CONFKEY_SECRET)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.secret = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_TIMEOUT, sizeof(CONFKEY_TIMEOUT)))
        {
            unsigned long ulval;
            if (0 == _safe_convert_ulong(val , &ulval))
            {
                G_tacplus_conf.timeout = (0 == ulval ? 5 : ulval);
                tac_timeout = G_tacplus_conf.timeout;
            }
        }
        else if (0 == strncmp(key, CONFKEY_DEBUG,
                              sizeof(CONFKEY_DEBUG)))
        {
            // debug is 1 for enable and 0 for disable
            G_tacplus_conf.debug = 1;
            // this probably doesn't do anything useful
            tac_debug_enable = G_tacplus_conf.debug;
        }
        else if (0 == strncmp(key, CONFKEY_SERVICE, sizeof(CONFKEY_SERVICE)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.service = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else if (0 == strncmp(key, CONFKEY_PROTOCOL,
                              sizeof(CONFKEY_PROTOCOL)))
        {
            if (bufleft < strlen(val) + 1)
            {
                errno = ERANGE;
                status = NSS_STATUS_TRYAGAIN;
                break;
            }

            G_tacplus_conf.protocol = offset;
            while ('\0' != *val)
            {
                *offset++ = *val++;
            }
            bufleft = buflen - (++offset - buffer);
        }
        else
        {
            syslog(LOG_WARNING, "nss_tacplus: unknown configuration key=`%s'", key);
        }
    }

    fclose(fp);
    return status;
}

static void _check_config(int cycle)
{
    struct stat conf_stat;

    memset(&conf_stat, 0, sizeof(conf_stat));
    if (   0 != stat(TACPLUS_CONF_FILE, &conf_stat)
        || conf_stat.st_mtime == G_tacplus_conf.mtime)
    {
        // short-circuit if we can't stat the configuration file
        // or if the modification time hasn't changed
        // NOTE: we'll also reread if mtime moves backwards
        if (G_tacplus_conf.debug)
        {
            syslog(LOG_DEBUG, "nss_tacplus: `%s' no change at cycle=%d", TACPLUS_CONF_FILE, cycle);
        }
        return;
    }

    if (G_tacplus_conf.debug)
    {
        syslog(LOG_INFO, "nss_tacplus: `%s' detected configuration change at cycle=%d", TACPLUS_CONF_FILE, cycle);
    }
    // reload our configuration!
}

/**
 * Initialize the module. This should be called only once.
 */
static void _initalize_tacplus(void)
{
    enum nss_status status = NSS_STATUS_SUCCESS;
    struct tacplus_conf_st *conf = &G_tacplus_conf;

    memset(&G_tacplus_conf, 0, sizeof(G_tacplus_conf));
    memset(&G_tacplus_confbuf, 0, sizeof(G_tacplus_confbuf));

    G_tacplus_started = time(NULL);


    status = _parse_config(G_tacplus_confbuf, sizeof(G_tacplus_confbuf));

    if (G_tacplus_conf.debug)
    {
        syslog(LOG_DEBUG, "nss_tacplus: started, uid=(%u:%u), gid=(%u:%u)",
               getuid(), geteuid(), getgid(), getegid());
    }
    conf->status = status;
    conf->errnum = errno;
}

/**
 * Normalize the `attribute' name of TACACS+ AV pairs into environment
 * variable-compatible format.
 *
 * Effectively, upper case all ASCII characters, and convert dash (`-')
 * to underscore (`_').
 *
 * NOTE: Currently operates by-contract, with little error handling. In
 *       particular we don't bounds checks the length of the output buffer
 *       beyond the use of an assert. This is an internal function, so it
 *       should be safe, but it'd be worth revisiting if utilization was
 *       ever changed.
 *
 * \param[in] name The original version of the attribute.
 * \param[in] namelen The length of `name'.
 * \param[out] obuf A buffer that will be populated with the normalized
 *                  name, which will always be
 * \param[in] buflen The length of the output buffer, which must be at
 *                   least namelen + 1 in length.
 */
static void _normalize_name(const char *name, size_t namelen,
                            char *obuf, size_t buflen)
{
    size_t i = 0;

    // buflen had better be longer than namelen
    assert(buflen > namelen);

    for (; i < namelen; ++i)
    {
        if ('-' == name[i])
        {
            obuf[i] = '_';
        }
        obuf[i] = toupper(name[i]);
    }

    obuf[i] = '\0';
}

static const char TAC_ATTR_UID[]   = "UID";
static const char TAC_ATTR_ROLE[]  = "ROLE"; // (admin, operator, ro)
static const char TAC_ATTR_HOME[]  = "HOME";
static const char TAC_ATTR_SHELL[] = "SHELL";

#define TAC_DEFAULT_HOME  "/"
#define TAC_DEFAULT_SHELL "/bin/bash"
#define TAC_VIEWER_SHELL  "/bin/px-shell"

typedef struct
{
    char* role;
    char* groupName;
} tacRoleGroupName;

static tacRoleGroupName TAC_ROLES[] =
{
    { "ADMINISTRATOR", "px_administrator" },
    { "OPERATOR",      "px_operator"      },
    { "VIEWER",        "px_viewer"        }
};
#define NUM_ROLES (sizeof(TAC_ROLES) / sizeof(tacRoleGroupName))

static const char *REQUIRED_TAC_ATTRS[] =
{
    TAC_ATTR_UID,
    TAC_ATTR_ROLE,
    NULL
};
#define REQUIRED_TAC_ATTRS_LEN (sizeof(REQUIRED_TAC_ATTRS) / sizeof(char*))

/**
 * ... more documentation ...
 */
static int _passwd_from_reply(const struct areply *reply, const char *name,
                              struct passwd *pw, char *buffer, size_t buflen,
                              int *errnop)
{
    struct tac_attrib* attr = NULL;
    enum nss_status    status = NSS_STATUS_SUCCESS;
    char*              offset = buffer;
    const char*        attr_found[REQUIRED_TAC_ATTRS_LEN] = { 0 };
    int                shell_opt_found = 0;
    int                role_is_viewer = 0;
    ptrdiff_t          bufleft = buflen - (offset - buffer);
    struct group*      group;
    int                role;
    
#define mark_attr_found(attrptr)                         \
    for (size_t i = 0; i < REQUIRED_TAC_ATTRS_LEN; ++i)  \
    {                                                    \
        if ((attrptr) == attr_found[i])                  \
        {                                                \
            break;                                       \
        }                                                \
        else if (NULL == attr_found[i])                  \
        {                                                \
            attr_found[i] = (attrptr);                   \
            break;                                       \
        }                                                \
    }

    // nullify the attr_good variable
    memset(attr_found, 0, sizeof(attr_found));

    // let's clear out the buffer -- this will simplify code below
    memset(buffer, '\0', buflen);

    // populate pw_name using the 'name' provided
    if (bufleft < strlen(name) + 1)
    {
        goto buffer_full;
    }

    // set pw_name and pw_gecos to the same value
    pw->pw_name = pw->pw_gecos = offset;
    while ('\0' != *name)
    {
        *offset++ = *name++;
    }
    bufleft = buflen - (++offset - buffer);

    // password is always notset, so use a constant
    pw->pw_passwd = (char*)NO_PASSWD;

    // set optional attributes
    pw->pw_dir   = TAC_DEFAULT_HOME;
    pw->pw_shell = TAC_DEFAULT_SHELL;

    attr = reply->attr;
    while (NULL != attr && NSS_STATUS_SUCCESS == status)
    {
        char *sep = NULL;

        sep = strchr(attr->attr, '=');
        if (NULL == sep)
        {
            sep = strchr(attr->attr, '*');
        }
        if (NULL != sep)
        {
            char tmp[attr->attr_len]; // non-portable, but works for GCC
            char *value = (sep + 1);  // value starts after seperator
            size_t namsz = sep - attr->attr;

            memset(tmp, '\0', sizeof(tmp));

            _normalize_name(attr->attr, namsz, tmp, sizeof(tmp));

            if (0 == strcmp(tmp, TAC_ATTR_UID))
            {
                unsigned long ulval;
                if (0 == _safe_convert_ulong(value , &ulval))
                {
                    pw->pw_uid = ulval;
                    mark_attr_found(TAC_ATTR_UID);
                }
                else
                {
                    *errnop = errno;
                    status = NSS_STATUS_TRYAGAIN;
                }
            }
            if (0 == strcmp(tmp, TAC_ATTR_ROLE))
            {
                // find GID that matches ROLE
                for (role = 0; role < NUM_ROLES; role++)
                {
                    if (strcasecmp(value, TAC_ROLES[role].role) == 0)
                    {
                        
                        // getgrnam(name)
                        if ((group = getgrnam(TAC_ROLES[role].groupName)) != NULL)
                        {
                            // found matching role
                            pw->pw_gid = group->gr_gid;
                            mark_attr_found(TAC_ATTR_ROLE);
                            if (strcmp(TAC_ROLES[role].role, "VIEWER") == 0)
                            {
                                role_is_viewer = 1;
                            }
                            break;
                        }
                        else
                        {
                            syslog(LOG_WARNING, "nss_tacplus: group %s not found", TAC_ROLES[role].groupName);
                        }
                    }
                }                        
            }
            if (0 == strcmp(tmp, TAC_ATTR_HOME))
            {
                if (bufleft < strlen(value) + 1)
                {
                    goto buffer_full;
                }

                pw->pw_dir = offset;
                while ('\0' != *value)
                {
                    *offset++ = *value++;
                }
                bufleft = buflen - (++offset - buffer);
            }
            if (0 == strcmp(tmp, TAC_ATTR_SHELL))
            {
                if (bufleft < strlen(value) + 1)
                {
                    goto buffer_full;
                }

                pw->pw_shell = offset;
                while ('\0' != *value)
                {
                    *offset++ = *value++;
                }
                bufleft = buflen - (++offset - buffer);
                shell_opt_found = 1;
            }
        }
        else
        {
            if (G_tacplus_conf.debug)
            {
                syslog(LOG_WARNING,
                       "nss_tacplus: invalid attribute `%s', no separator",
                       attr->attr);
            }
        }

        attr = attr->next;
    }

    for (size_t o = 0; NULL != REQUIRED_TAC_ATTRS[o]; ++o)
    {
        const char *cur = REQUIRED_TAC_ATTRS[o];
        bool seen = false;

        for (size_t i = 0; NULL != attr_found[i]; ++i)
        {
            if (cur == attr_found[i])
            {
                seen = true;
                break;
            }
        }

        if (!seen)
        {
            syslog(LOG_WARNING, "nss_tacplus: missing required attribute '%s'", cur);
            status = NSS_STATUS_NOTFOUND;
        }
    }

    // if no shell opt and role is VIEWER set shell to VIEWER shell
    if (!shell_opt_found && role_is_viewer)
    {
        pw->pw_shell = TAC_VIEWER_SHELL;
    }
    
    return status;

buffer_full:
    *errnop = ERANGE;
    return NSS_STATUS_TRYAGAIN;
}

/**
 * ... document me ...
 */
enum nss_status _nss_tacplus_getpwnam_r(const char *name, struct passwd *pw,
                                        char *buffer, size_t buflen,
                                        int *errnop)
{
    enum nss_status status = NSS_STATUS_NOTFOUND;
    int tac_fd = -1;
    struct addrinfo *server = NULL;
    time_t now = -1;
    uint32_t cycle = 0;

    (void)pthread_once(&G_tacplus_initialized, &_initalize_tacplus);
    now = time(NULL);

    // check to see if we should re-read our configuration
    // once per 32 second cycle
    cycle = (now - G_tacplus_started) >> 5;
    if (   NSS_STATUS_SUCCESS != G_tacplus_conf.status
        || cycle > G_tacplus_cycles)
    {
        G_tacplus_cycles = cycle;
        _check_config(cycle);
    }
    else
    {
        G_tacplus_cycles = cycle;
    }

    if (NSS_STATUS_SUCCESS != G_tacplus_conf.status)
    {
        status = G_tacplus_conf.status;
        *errnop = G_tacplus_conf.errnum;

        assert(NULL == G_tacplus_conf.servers);
    }

    // Iterate through our servers linked list, stop when we get an answer
    // that isn't NOTFOUND. Since we're twisting TACACS+ authorization
    // functionality to provide this facility, we treat AUTHOR_STATUS_FAIL,
    // AUTHOR_STATUS_ERROR, AUTHOR_STATUS_FAIL as "soft" fails, and just
    // move on to the next server. Doing otherwise would result in potentially
    // unexpected behaviors if the user is provisioned on server->ai_next, but
    // not on server.
    for (server = G_tacplus_conf.servers;
         NSS_STATUS_NOTFOUND == status && NULL != server;
         server = server->ai_next)
    {
        void *sin_addr = NULL;

        // the first member of sockaddr_in and sockaddr_in6 are the same, so
        // this should always work.
        uint16_t port = ntohs(((struct sockaddr_in *)server->ai_addr)->sin_port);

        // this is ugly, but we need to differentiate IPv6 vs. IPv4 addresses
        // (in practice, this may not be necessary, as I'm not certain if the
        // remainder of this code is capable of handling IPv6, yet.)
        sin_addr = (  AF_INET6 == server->ai_family
                    ? (void*)&((struct sockaddr_in6 *)server->ai_addr)->sin6_addr
                    : (void*)&((struct sockaddr_in *)server->ai_addr)->sin_addr);
        inet_ntop(server->ai_family, sin_addr, buffer, buflen);

        if (G_tacplus_conf.debug)
        {
            syslog(LOG_INFO, "nss_tacplus: begin lookup: user=`%s', server=`%s:%d'",
                   name, buffer, port);
        }
        
        // connect to the current server
        errno = 0;
        tac_fd = tac_connect_single(server, G_tacplus_conf.secret, NULL, G_tacplus_conf.timeout);

        if (0 > tac_fd)
        {
            char errtext[256];
            int errnum = errno;

            strerror_r(errnum, errtext, sizeof(errtext));
            syslog(LOG_WARNING,
                   "nss_tacplus: Connection to TACACS+ server failed: server=`%s:%d', "
                   "errno=%d, errtext=`%s'",
                   buffer, port, errnum, errtext);

             // upon failure, simply move on to the next server in the list
            continue;
        }
        else
        {
            int rv = -1;
            struct tac_attrib *attr = NULL;

            tac_add_attrib(&attr, "service", G_tacplus_conf.service);
            tac_add_attrib(&attr, "protocol", G_tacplus_conf.protocol);

            rv = tac_author_send(tac_fd, name, G_tacplus_conf.protocol,
                                 "unknown", attr);

            tac_free_attrib(&attr);

            if (0 > rv)
            {
                status = NSS_STATUS_TRYAGAIN;
            }
            else
            {
                struct areply reply;

                memset(&reply, '\0', sizeof(reply));
                tac_author_read(tac_fd, &reply);

                if (   (AUTHOR_STATUS_PASS_ADD == reply.status)
                    || (AUTHOR_STATUS_PASS_REPL == reply.status))
                {
                    if (G_tacplus_conf.debug)
                    {
                        syslog(LOG_INFO,
                               "nss_tacplus: found match: user=`%s', server=`%s:%d', "
                               "status=%d, attributes? %s",
                               name, buffer, port, reply.status,
                               (NULL == reply.attr ? "no" : "yes"));
                    }
                    status = _passwd_from_reply(&reply, name, pw, buffer,
                                                buflen, errnop);
                }
                else
                {
                    if (G_tacplus_conf.debug)
                    {
                        syslog(LOG_INFO,
                               "nss_tacplus: lookup failed: user=`%s', server=`%s:%d', "
                               "status=%d, msg=%s", name, buffer, port,
                               reply.status, reply.msg);
                    }
                }
                if (NULL != reply.attr)
                {
                    tac_free_attrib(&reply.attr);
                }
                free(reply.msg);
            }
        }

        // XXX: there is a potential efficiency to be gained by not
        //      reopening our sockets all the time, but I'm not
        //      convinced it's worth it, especially since we require
        //      nscd to operate, anyhow.
        close(tac_fd);
    }

    return status;
}
