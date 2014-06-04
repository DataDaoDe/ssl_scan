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
          write_header(parts[0], parts[1])
          scanner = SSLScan::Scanner.new(parts[0], parts[1].to_i)
        else
          write_header(parts[0])
          scanner = SSLScan::Scanner.new(parts[0])
        end
        write_ciphers(scanner)
        write_preferred_ciphers(scanner)
        @results << scanner.results
      end

    end # Host
  end # Commands
end # SSLScan
