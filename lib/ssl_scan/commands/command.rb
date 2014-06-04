require "stringio"

module SSLScan
  module Commands
    class Command
      attr_accessor :results, :options, :stream

      def initialize(results=[], stream=nil)
        @results = results
        @stream  = stream || STDOUT
      end

      def execute
        raise "Implement"
      end

      # Display Methods
      def write_header(host, port=443)
        stream.printf "\nTesting SSL server #{host} on port #{port}"
      end

      def write_preferred_ciphers(scanner)
        stream.printf("\nServer Preferred Cipher(s)\n")
        ciphers = scanner.get_preferred_ciphers
        ciphers.each { |c| stream.printf("%s", c) }
      end

      def write_ciphers(scanner=nil)
        stream.printf "\nSupported Server Cipher(s):\n"
        scanner.scan do |ssl_version, cipher_name, alg_length, status|
          unless options.no_failed && status == :failed
            stream.printf "%12s %10s %10s %s\n", status, ssl_version, "#{alg_length} bits",  cipher_name
          end
        end
        scanner
      end

    end
  end
end
