require "ssl_scan/compat"
require "ssl_scan/scanner"
require "ssl_scan/result"
require "optparse"
require "ostruct"

module SSLScan
  class Main

    attr_accessor :options

    def main(argc, argv)
      @options = self.class.parse_options(argv)
    end

    alias_method :run, :main

    def self.parse_options(args)
      options = OpenStruct.new
      options.file = false
      options.no_failed = false

      opts = OptionParser.new do |opts|
        opts.banner = "Command: ssl_scan [options] [host:port | host]"

        opts.separator ""
        opts.separator "Options:"

        # File containing list of hosts to check
        opts.on( "-t", 
                 "--targets FILE",
                 "A file containing a list of hosts to check. Hosts can  be supplied  with ports (i.e. host:port).",
                 "Load the lists if file is supplied") do |file|
          options.file = file
        end

        # List only accepted ciphers
        opts.on( "--no-failed",
                 "List only accepted ciphers",
                 "Load the lists if file is supplied") do |file|
          options.no_failed = true
        end
      end

      opts.parse!(args)
      options
    end

  end
end