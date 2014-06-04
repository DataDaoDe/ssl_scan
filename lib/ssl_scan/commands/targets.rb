module SSLScan
  module Commands
    class Targets < Command

      attr_accessor :file, :hosts

      def initialize(filename="", options)
        super()
        @file = File.read(filename)
        @hosts = @file.split("\n").map(&:strip).select { |h| h.length > 0 }
        @options = options
      end

      def execute
        hosts.each do |host|
          parts = host.split(":")
          if parts.length == 2
            display_header(parts[0], parts[1])
            scanner = SSLScan::Scanner.new(parts[0], parts[1].to_i)
          else
            display_header(host)
            scanner = SSLScan::Scanner.new(parts[0])
          end
          display_ciphers(scanner)
          @results << scanner.results
        end
      end

    end
  end
end