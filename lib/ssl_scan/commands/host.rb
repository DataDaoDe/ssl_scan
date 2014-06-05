module SSLScan
  module Commands
    class Host < Command
      attr_accessor :hostname, :options

      def initialize(hostname, options={}, output=nil)
        super([], output)
        @hostname = hostname
        @options  = options
      end

      def execute
        parts = hostname.split(":")
        if parts.length == 2
          scanner = SSLScan::Scanner.new(parts[0], parts[1].to_i)
        else
          scanner = SSLScan::Scanner.new(parts[0])
        end
        # If we can't get any SSL connection, then don't bother testing
        # individual ciphers.
        if [:rejected, :failed].include?(scanner.test_ssl) and [:rejected, :failed].include?(scanner.test_tls)
          errors << "SSL Connection failed"
          return false
        end

        if parts.length == 2
          write_header(parts[0], parts[1])
        else
          write_header(parts[0])
        end

        if options.only_cert
          scanner.get_first_valid_cert
          @results << scanner.results
        else
          write_ciphers(scanner)
          write_preferred_ciphers(scanner)
          @results << scanner.results
        end
      end

    end # Host
  end # Commands
end # SSLScan
