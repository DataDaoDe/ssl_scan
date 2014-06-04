require "ssl_scan/compat"
require "ssl_scan/version"
require "ssl_scan/scanner"
require "ssl_scan/result"
require "openssl"
require "optparse"
require "ostruct"

require "commands/targets"
require "commands/"

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
      elsif (options.only_ssl2 || options.only_ssl3 || options.only_tls1 )

      else
        # Run the standard use case
      end
    end

    alias_method :run, :main

    def self.show_version_info
      printf("ssl_scan version %s\n%s\n%s\n", VERSION::STRING, WEBSITE, COPYRIGHT)
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