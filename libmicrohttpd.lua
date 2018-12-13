local ffi=require"ffi"

ffi.cdef[[
typedef int MHD_socket;
typedef uint32_t socklen_t;
typedef int32_t fd_mask;
typedef struct {
  fd_mask fds_bits[1024/(sizeof(fd_mask) *8)];
} fd_set;
typedef unsigned long long MHD_UNSIGNED_LONG_LONG;
typedef size_t off_t;

// library header version used to construct this FFI cdef:
//MHD_VERSION 0x00096200

const char *
MHD_get_reason_phrase_for (unsigned int code);

struct MHD_Daemon;
struct MHD_Connection;
struct MHD_Response;
struct MHD_PostProcessor;

enum MHD_FLAG
{
  MHD_NO_FLAG = 0,
  MHD_USE_ERROR_LOG = 1,
  MHD_USE_DEBUG = 1,
  MHD_USE_TLS = 2,
  MHD_USE_THREAD_PER_CONNECTION = 4,
  MHD_USE_INTERNAL_POLLING_THREAD = 8,
  MHD_USE_IPv6 = 16,
  MHD_USE_PEDANTIC_CHECKS = 32,
  MHD_USE_POLL = 64,
  MHD_USE_POLL_INTERNAL_THREAD = 72, // MHD_USE_POLL | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_SUPPRESS_DATE_NO_CLOCK = 128,
  MHD_USE_NO_LISTEN_SOCKET = 256,
  MHD_USE_EPOLL = 512,
  MHD_USE_EPOLL_INTERNAL_THREAD = 520, // MHD_USE_EPOLL | MHD_USE_INTERNAL_POLLING_THREAD,
  MHD_USE_ITC = 1024,
  MHD_USE_DUAL_STACK = 2064, // MHD_USE_IPv6 | 2048,
  MHD_USE_TURBO = 4096,
  MHD_ALLOW_SUSPEND_RESUME = 9216, // 8192 | MHD_USE_ITC,
  MHD_USE_TCP_FASTOPEN = 16384,
  MHD_ALLOW_UPGRADE = 32768,
  MHD_USE_AUTO = 65536,
  MHD_USE_AUTO_INTERNAL_THREAD = 65544 // MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD
};

typedef void
(*MHD_LogCallback)(void *cls,
                   const char *fm,
                   va_list ap);

typedef int
(*MHD_PskServerCredentialsCallback)(void *cls,
				    const struct MHD_Connection *connection,
				    const char *username,
				    void **psk,
				    size_t *psk_size);

enum MHD_OPTION
{
  MHD_OPTION_END = 0,
  MHD_OPTION_CONNECTION_MEMORY_LIMIT = 1,
  MHD_OPTION_CONNECTION_LIMIT = 2,
  MHD_OPTION_CONNECTION_TIMEOUT = 3,
  MHD_OPTION_NOTIFY_COMPLETED = 4,
  MHD_OPTION_PER_IP_CONNECTION_LIMIT = 5,
  MHD_OPTION_SOCK_ADDR = 6,
  MHD_OPTION_URI_LOG_CALLBACK = 7,
  MHD_OPTION_HTTPS_MEM_KEY = 8,
  MHD_OPTION_HTTPS_MEM_CERT = 9,
  MHD_OPTION_HTTPS_CRED_TYPE = 10,
  MHD_OPTION_HTTPS_PRIORITIES = 11,
  MHD_OPTION_LISTEN_SOCKET = 12,
  MHD_OPTION_EXTERNAL_LOGGER = 13,
  MHD_OPTION_THREAD_POOL_SIZE = 14,
  MHD_OPTION_ARRAY = 15,
  MHD_OPTION_UNESCAPE_CALLBACK = 16,
  MHD_OPTION_DIGEST_AUTH_RANDOM = 17,
  MHD_OPTION_NONCE_NC_SIZE = 18,
  MHD_OPTION_THREAD_STACK_SIZE = 19,
  MHD_OPTION_HTTPS_MEM_TRUST = 20,
  MHD_OPTION_CONNECTION_MEMORY_INCREMENT = 21,
  MHD_OPTION_HTTPS_CERT_CALLBACK = 22,
  MHD_OPTION_TCP_FASTOPEN_QUEUE_SIZE = 23,
  MHD_OPTION_HTTPS_MEM_DHPARAMS = 24,
  MHD_OPTION_LISTENING_ADDRESS_REUSE = 25,
  MHD_OPTION_HTTPS_KEY_PASSWORD = 26,
  MHD_OPTION_NOTIFY_CONNECTION = 27,
  MHD_OPTION_LISTEN_BACKLOG_SIZE = 28,
  MHD_OPTION_STRICT_FOR_CLIENT = 29,
  MHD_OPTION_GNUTLS_PSK_CRED_HANDLER = 30
};

struct MHD_OptionItem
{
  enum MHD_OPTION option;
  intptr_t value;
  void *ptr_value;
};

enum MHD_ValueKind
{
  MHD_RESPONSE_HEADER_KIND = 0,
  MHD_HEADER_KIND = 1,
  MHD_COOKIE_KIND = 2,
  MHD_POSTDATA_KIND = 4,
  MHD_GET_ARGUMENT_KIND = 8,
  MHD_FOOTER_KIND = 16
};

enum MHD_RequestTerminationCode
{
  MHD_REQUEST_TERMINATED_COMPLETED_OK = 0,
  MHD_REQUEST_TERMINATED_WITH_ERROR = 1,
  MHD_REQUEST_TERMINATED_TIMEOUT_REACHED = 2,
  MHD_REQUEST_TERMINATED_DAEMON_SHUTDOWN = 3,
  MHD_REQUEST_TERMINATED_READ_ERROR = 4,
  MHD_REQUEST_TERMINATED_CLIENT_ABORT = 5
};

enum MHD_ConnectionNotificationCode
{
  MHD_CONNECTION_NOTIFY_STARTED = 0,
  MHD_CONNECTION_NOTIFY_CLOSED = 1
};

union MHD_ConnectionInfo
{
  int /* enum gnutls_cipher_algorithm */ cipher_algorithm;
  int /* enum gnutls_protocol */ protocol;
  int /* MHD_YES or MHD_NO */ suspended;
  unsigned int connection_timeout;
  MHD_socket connect_fd;
  size_t header_size;
  void * /* gnutls_session_t */ tls_session;
  void * /* gnutls_x509_crt_t */ client_cert;
  struct sockaddr *client_addr;
  struct MHD_Daemon *daemon;
  void *socket_context;
};

enum MHD_ConnectionInfoType
{
  MHD_CONNECTION_INFO_CIPHER_ALGO,
  MHD_CONNECTION_INFO_PROTOCOL,
  MHD_CONNECTION_INFO_CLIENT_ADDRESS,
  MHD_CONNECTION_INFO_GNUTLS_SESSION,
  MHD_CONNECTION_INFO_GNUTLS_CLIENT_CERT,
  MHD_CONNECTION_INFO_DAEMON,
  MHD_CONNECTION_INFO_CONNECTION_FD,
  MHD_CONNECTION_INFO_SOCKET_CONTEXT,
  MHD_CONNECTION_INFO_CONNECTION_SUSPENDED,
  MHD_CONNECTION_INFO_CONNECTION_TIMEOUT,
  MHD_CONNECTION_INFO_REQUEST_HEADER_SIZE
};

enum MHD_DaemonInfoType
{
  MHD_DAEMON_INFO_KEY_SIZE,
  MHD_DAEMON_INFO_MAC_KEY_SIZE,
  MHD_DAEMON_INFO_LISTEN_FD,
  MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,
  MHD_DAEMON_INFO_EPOLL_FD = MHD_DAEMON_INFO_EPOLL_FD_LINUX_ONLY,
  MHD_DAEMON_INFO_CURRENT_CONNECTIONS,
  MHD_DAEMON_INFO_FLAGS,
  MHD_DAEMON_INFO_BIND_PORT
};

typedef void
(*MHD_PanicCallback) (void *cls,
                      const char *file,
                      unsigned int line,
                      const char *reason);

typedef int
(*MHD_AcceptPolicyCallback) (void *cls,
                             const struct sockaddr *addr,
                             socklen_t addrlen);

typedef int
(*MHD_AccessHandlerCallback) (void *cls,
                              struct MHD_Connection *connection,
                              const char *url,
                              const char *method,
                              const char *version,
                              const char *upload_data,
                              size_t *upload_data_size,
                              void **con_cls);

typedef void
(*MHD_RequestCompletedCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **con_cls,
                                 enum MHD_RequestTerminationCode toe);

typedef void
(*MHD_NotifyConnectionCallback) (void *cls,
                                 struct MHD_Connection *connection,
                                 void **socket_context,
                                 enum MHD_ConnectionNotificationCode toe);

typedef int
(*MHD_KeyValueIterator) (void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         const char *value);

typedef ssize_t
(*MHD_ContentReaderCallback) (void *cls,
                              uint64_t pos,
                              char *buf,
                              size_t max);

typedef void
(*MHD_ContentReaderFreeCallback) (void *cls);

typedef int
(*MHD_PostDataIterator) (void *cls,
                         enum MHD_ValueKind kind,
                         const char *key,
                         const char *filename,
                         const char *content_type,
                         const char *transfer_encoding,
                         const char *data,
                         uint64_t off,
                         size_t size);

/* **************** Daemon handling functions ***************** */

struct MHD_Daemon *
MHD_start_daemon_va (unsigned int flags,
		     uint16_t port,
		     MHD_AcceptPolicyCallback apc, void *apc_cls,
		     MHD_AccessHandlerCallback dh, void *dh_cls,
		     va_list ap);

struct MHD_Daemon *
MHD_start_daemon (unsigned int flags,
		  uint16_t port,
		  MHD_AcceptPolicyCallback apc, void *apc_cls,
		  MHD_AccessHandlerCallback dh, void *dh_cls,
		  ...);

MHD_socket
MHD_quiesce_daemon (struct MHD_Daemon *daemon);

void
MHD_stop_daemon (struct MHD_Daemon *daemon);

int
MHD_add_connection (struct MHD_Daemon *daemon,
		    MHD_socket client_socket,
		    const struct sockaddr *addr,
		    socklen_t addrlen);

int
MHD_get_fdset (struct MHD_Daemon *daemon,
               fd_set *read_fd_set,
               fd_set *write_fd_set,
	       fd_set *except_fd_set,
	       MHD_socket *max_fd);

int
MHD_get_fdset2 (struct MHD_Daemon *daemon,
		fd_set *read_fd_set,
		fd_set *write_fd_set,
		fd_set *except_fd_set,
		MHD_socket *max_fd,
		unsigned int fd_setsize);

int
MHD_get_timeout (struct MHD_Daemon *daemon,
		 MHD_UNSIGNED_LONG_LONG *timeout);

int
MHD_run (struct MHD_Daemon *daemon);

int
MHD_run_from_select (struct MHD_Daemon *daemon,
		     const fd_set *read_fd_set,
		     const fd_set *write_fd_set,
		     const fd_set *except_fd_set);

/* **************** Connection handling functions ***************** */

int
MHD_get_connection_values (struct MHD_Connection *connection,
                           enum MHD_ValueKind kind,
                           MHD_KeyValueIterator iterator,
                           void *iterator_cls);

int
MHD_set_connection_value (struct MHD_Connection *connection,
                          enum MHD_ValueKind kind,
                          const char *key,
			  const char *value);

void
MHD_set_panic_func (MHD_PanicCallback cb, void *cls);

size_t
MHD_http_unescape (char *val);

const char *
MHD_lookup_connection_value (struct MHD_Connection *connection,
			     enum MHD_ValueKind kind,
			     const char *key);

int
MHD_queue_response (struct MHD_Connection *connection,
                    unsigned int status_code,
		    struct MHD_Response *response);

void
MHD_suspend_connection (struct MHD_Connection *connection);

void
MHD_resume_connection (struct MHD_Connection *connection);


/* **************** Response manipulation functions ***************** */

enum MHD_ResponseFlags
{
  MHD_RF_NONE = 0,
  MHD_RF_HTTP_VERSION_1_0_ONLY = 1,
  MHD_RF_HTTP_VERSION_1_0_RESPONSE = 2
};

enum MHD_ResponseOptions
{
  MHD_RO_END = 0
};

int
MHD_set_response_options (struct MHD_Response *response,
                          enum MHD_ResponseFlags flags,
                          ...);

struct MHD_Response *
MHD_create_response_from_callback (uint64_t size,
				   size_t block_size,
				   MHD_ContentReaderCallback crc, void *crc_cls,
				   MHD_ContentReaderFreeCallback crfc);

struct MHD_Response *
MHD_create_response_from_data (size_t size,
			       void *data,
			       int must_free,
			       int must_copy);

enum MHD_ResponseMemoryMode
{
  MHD_RESPMEM_PERSISTENT,
  MHD_RESPMEM_MUST_FREE,
  MHD_RESPMEM_MUST_COPY
};

struct MHD_Response *
MHD_create_response_from_buffer (size_t size,
				 void *buffer,
				 enum MHD_ResponseMemoryMode mode);

struct MHD_Response *
MHD_create_response_from_buffer_with_free_callback (size_t size,
						    void *buffer,
						    MHD_ContentReaderFreeCallback crfc);

struct MHD_Response *
MHD_create_response_from_fd (size_t size,
                               int fd);

struct MHD_Response *
MHD_create_response_from_fd64 (uint64_t size,
                               int fd);

struct MHD_Response *
MHD_create_response_from_fd_at_offset (size_t size,
                                       int fd,
                                       off_t offset);

struct MHD_Response *
MHD_create_response_from_fd_at_offset64 (uint64_t size,
                                         int fd,
                                         uint64_t offset);

enum MHD_UpgradeAction
{
  MHD_UPGRADE_ACTION_CLOSE = 0
};

struct MHD_UpgradeResponseHandle;

int
MHD_upgrade_action (struct MHD_UpgradeResponseHandle *urh,
                    enum MHD_UpgradeAction action,
                    ...);

typedef void
(*MHD_UpgradeHandler)(void *cls,
                      struct MHD_Connection *connection,
                      void *con_cls,
                      const char *extra_in,
                      size_t extra_in_size,
                      MHD_socket sock,
                      struct MHD_UpgradeResponseHandle *urh);

struct MHD_Response *
MHD_create_response_for_upgrade (MHD_UpgradeHandler upgrade_handler,
				 void *upgrade_handler_cls);

void
MHD_destroy_response (struct MHD_Response *response);

int
MHD_add_response_header (struct MHD_Response *response,
                         const char *header,
			 const char *content);

int
MHD_add_response_footer (struct MHD_Response *response,
                         const char *footer,
			 const char *content);

int
MHD_del_response_header (struct MHD_Response *response,
                         const char *header,
			 const char *content);

int
MHD_get_response_headers (struct MHD_Response *response,
                          MHD_KeyValueIterator iterator, void *iterator_cls);

const char *
MHD_get_response_header (struct MHD_Response *response,
			 const char *key);


/* ********************** PostProcessor functions ********************** */

struct MHD_PostProcessor *
MHD_create_post_processor (struct MHD_Connection *connection,
			   size_t buffer_size,
			   MHD_PostDataIterator iter, void *iter_cls);

int
MHD_post_process (struct MHD_PostProcessor *pp,
                  const char *post_data, size_t post_data_len);

int
MHD_destroy_post_processor (struct MHD_PostProcessor *pp);


/* ********************* Digest Authentication functions *************** */

char *
MHD_digest_auth_get_username (struct MHD_Connection *connection);

void
MHD_free (void *ptr);

enum MHD_DigestAuthAlgorithm {
  MHD_DIGEST_ALG_AUTO = 0,
  MHD_DIGEST_ALG_MD5,
  MHD_DIGEST_ALG_SHA256
};

int
MHD_digest_auth_check2 (struct MHD_Connection *connection,
			const char *realm,
			const char *username,
			const char *password,
			unsigned int nonce_timeout,
			enum MHD_DigestAuthAlgorithm algo);

int
MHD_digest_auth_check (struct MHD_Connection *connection,
		       const char *realm,
		       const char *username,
		       const char *password,
		       unsigned int nonce_timeout);

int
MHD_digest_auth_check_digest2 (struct MHD_Connection *connection,
			       const char *realm,
			       const char *username,
			       const uint8_t *digest,
                               size_t digest_size,
			       unsigned int nonce_timeout,
			       enum MHD_DigestAuthAlgorithm algo);

int
MHD_digest_auth_check_digest (struct MHD_Connection *connection,
			      const char *realm,
			      const char *username,
			      const uint8_t digest[16],
			      unsigned int nonce_timeout);

int
MHD_queue_auth_fail_response2 (struct MHD_Connection *connection,
			       const char *realm,
			       const char *opaque,
			       struct MHD_Response *response,
			       int signal_stale,
			       enum MHD_DigestAuthAlgorithm algo);

int
MHD_queue_auth_fail_response (struct MHD_Connection *connection,
			      const char *realm,
			      const char *opaque,
			      struct MHD_Response *response,
			      int signal_stale);

char *
MHD_basic_auth_get_username_password (struct MHD_Connection *connection,
				      char** password);

int
MHD_queue_basic_auth_fail_response (struct MHD_Connection *connection,
				    const char *realm,
				    struct MHD_Response *response);

/* ********************** generic query functions ********************** */

const union MHD_ConnectionInfo *
MHD_get_connection_info (struct MHD_Connection *connection,
			 enum MHD_ConnectionInfoType info_type,
			 ...);

enum MHD_CONNECTION_OPTION
{
  MHD_CONNECTION_OPTION_TIMEOUT
};

int
MHD_set_connection_option (struct MHD_Connection *connection,
			   enum MHD_CONNECTION_OPTION option,
			   ...);

union MHD_DaemonInfo
{
  size_t key_size;
  size_t mac_key_size;
  MHD_socket listen_fd;
  uint16_t port;
  int epoll_fd;
  unsigned int num_connections;
  enum MHD_FLAG flags;
};

const union MHD_DaemonInfo *
MHD_get_daemon_info (struct MHD_Daemon *daemon,
		     enum MHD_DaemonInfoType info_type,
		     ...);

const char*
MHD_get_version (void);

enum MHD_FEATURE
{
  MHD_FEATURE_MESSAGES = 1,
  MHD_FEATURE_TLS = 2,
  MHD_FEATURE_SSL = 2,
  MHD_FEATURE_HTTPS_CERT_CALLBACK = 3,
  MHD_FEATURE_IPv6 = 4,
  MHD_FEATURE_IPv6_ONLY = 5,
  MHD_FEATURE_POLL = 6,
  MHD_FEATURE_EPOLL = 7,
  MHD_FEATURE_SHUTDOWN_LISTEN_SOCKET = 8,
  MHD_FEATURE_SOCKETPAIR = 9,
  MHD_FEATURE_TCP_FASTOPEN = 10,
  MHD_FEATURE_BASIC_AUTH = 11,
  MHD_FEATURE_DIGEST_AUTH = 12,
  MHD_FEATURE_POSTPROCESSOR = 13,
  MHD_FEATURE_HTTPS_KEY_PASSWORD = 14,
  MHD_FEATURE_LARGE_FILE = 15,
  MHD_FEATURE_THREAD_NAMES = 16,
  MHD_THREAD_NAMES = 16,
  MHD_FEATURE_UPGRADE = 17,
  MHD_FEATURE_RESPONSES_SHARED_FD = 18,
  MHD_FEATURE_AUTODETECT_BIND_PORT = 19,
  MHD_FEATURE_AUTOSUPPRESS_SIGPIPE = 20,
  MHD_FEATURE_SENDFILE = 21,
  MHD_FEATURE_THREADS
};

int
MHD_is_feature_supported (enum MHD_FEATURE feature);
]]

return ffi.load("microhttpd")
