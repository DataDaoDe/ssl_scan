module SSLScan
  module Commands
    class Targets

      attr_accesssor :file, :hosts, :results

      def initialize(filename="")
        @file = File.read(filename)
        @hosts = @file.split("\n").map(:strip).select { |h| h.length > 0 }
      end

      def execute
        @results = []
        @hosts.each do |host|
          parts = host.split(":")
          if parts.length == 2
            scanner = SSLScan::Scanner.new(parts[0], parts[1].to_i)
          else
            scanner = SSLScan::Scanner.new(parts[0])
          end
          @results << scanner.scan
        end
      end

    end
  end
end