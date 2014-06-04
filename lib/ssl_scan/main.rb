require "ssl_scan/compat"
require "ssl_scan/version"
require "ssl_scan/scanner"
require "ssl_scan/result"
require "openssl"
require "optparse"
require "ostruct"

require "ssl_scan/commands/command"
require "ssl_scan/commands/targets"
require "ssl_scan/commands/only_certain_ssl"
require "ssl_scan/commands/host"

module SSLScan
  class Main

    EXIT_SUCCESS = 0
    EXIT_FAILURE = 1

    WEBSITE   = "https://www.testcloud.de"
    COPYRIGHT = "Copyright (C) John Faucett #{Time.now.year}"

    attr_accessor :options

    def main(argc, argv)
      @options = self.class.parse_options(argv)

      if options.file
        command = SSLScan::Commands::Targets.new(options.file)
        command.execute
      else
        valid = true
        port  = 443
        error_msg = "Host invalid"
        begin
          host = argv.last
          if !host
            error_msg = "Host not given"
            valid = false
          else
            host_parts = host.split(":")
            host = host_parts.first
            port = host_parts.last.to_i if host_parts.last != host
            ::Socket.gethostbyname(host)
          end
        rescue ::SocketError => ex
          error_msg = ex.message
          valid = false
        end

        unless valid
          printf("Error: %s\n", error_msg)
          exit(EXIT_FAILURE)
        end

        if (options.only_ssl2 || options.only_ssl3 || options.only_tls1 )
          command = SSLScan::Commands::OnlyCertainSSL.new(options)
          command.execute
        else
          command = SSLScan::Commands::Host.new(argv.last)
          command.execute
        end
      end

      show_certificate(command.results.first.cert)
    end

    alias_method :run, :main

    def self.show_version_info
      printf("ssl_scan version %s\n%s\n%s\n", VERSION::STRING, WEBSITE, COPYRIGHT)
    end

    def show_certificate(cert)
      printf("SSL Certificate:\n")
      printf("  Version: %d\n", cert.version)
      printf("  Serial Number: %s\n", cert.serial.to_s(16))
      printf("  Signature Algorithm: %s\n", cert.signature_algorithm)
      printf("  Issuer: %s\n", cert.issuer.to_s)
      printf("  Not valid before: %s\n", cert.not_before.to_s)
      printf("  Not valid after: %s\n", cert.not_after.to_s)
      printf("  Subject: %s\n", cert.subject.to_s)
      printf("  %s", cert.public_key.to_text)

      # TODO: Implement extensions (see: cert.extensions)
    end

    def self.parse_options(args)
      options = OpenStruct.new
      options.file = false
      options.no_failed = false
      options.only_ssl2 = false
      options.only_ssl3 = false
      options.only_tls1 = false

      opts = OptionParser.new do |opts|
        opts.banner = "Command: ssl_scan [options] [host:port | host]"

        opts.separator ""
        opts.separator "Options:"

        # File containing list of hosts to check
        opts.on( "-t", 
                 "--targets FILE",
                 "A file containing a list of hosts to check with syntax ( host | host:port).") do |filename|
          options.file = filename
        end

        # List only accepted ciphers
        opts.on( "--no-failed",
                 "List only accepted ciphers.") do
          options.no_failed = true
        end

        opts.on( "--ssl2",
                 "Only check SSLv2 ciphers.") do
          options.only_ssl2 = true
        end

        opts.on( "--ssl3",
                 "Only check SSLv3 ciphers.") do
          options.only_ssl3 = true
        end

        opts.on( "--tls1",
                 "Only check TLSv1 ciphers.") do
          options.only_tls1 = true
        end

        opts.on( "-d",
                 "--debug",
                 "Print any SSL errors to stderr.") do
          OpenSSL.debug = true
        end

        opts.on_tail( "-h",
                      "--help",
                      "Display the help text you are now reading.") do
          puts opts
          exit(EXIT_SUCCESS)
        end

        opts.on_tail( "-v",
                      "--version",
                      "Display the program version.") do
          show_version_info
          exit(EXIT_SUCCESS)
        end

      end

      opts.parse!(args)
      options.freeze
    end

  end
end