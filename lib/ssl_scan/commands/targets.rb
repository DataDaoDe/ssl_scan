module SSLScan
  module Commands
    class Targets < Command

      attr_accessor :file, :hosts

      def initialize(filename="", options={}, output=nil)
        super([], output)
        @file = File.read(filename)
        @hosts = @file.split("\n").map(&:strip).select { |h| h.length > 0 }
        @options = options
      end

      def execute
        hosts.each do |host|
          parts = host.split(":")
          if parts.length == 2
            write_header(parts[0], parts[1])
            scanner = SSLScan::Scanner.new(parts[0], parts[1].to_i)
          else
            write_header(host)
            scanner = SSLScan::Scanner.new(parts[0])
          end
          write_ciphers(scanner)
          write_preferred_ciphers(scanner)
          @results << scanner.results
        end
        @results
      end

    end
  end
end
