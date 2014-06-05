require "socket"
require "openssl"

require "ssl_scan/version"
require "ssl_scan/compat"
require "ssl_scan/result"
require "ssl_scan/util"
require "timeout"
require "thread"
require "ssl_scan/sync/thread_safe"
require "ssl_scan/io/stream"
require "ssl_scan/io/stream_server"
require "ssl_scan/socket"
require "ssl_scan/socket/tcp"
require "ssl_scan/scanner"

module SSLScan
end
