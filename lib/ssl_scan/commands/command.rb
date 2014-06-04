module SSLScan
  module Commands
    class Command
      attr_accessor :results, :options

      def initialize
        @results = []
      end

      def execute
        raise "Implement"
      end

      # Display Methods
      def display_header(host, port=443)
        printf "\nTesting SSL server #{host} on port #{port}"
      end

      def display_ciphers(scanner=nil)
        printf "\nSupported Server Cipher(s):\n"
        scanner.scan do |ssl_version, cipher_name, alg_length, status|
          unless options.no_failed && status == :failed
            printf "%12s %10s %10s %s\n", status, ssl_version, "#{alg_length} bits",  cipher_name
          end
        end
        scanner
      end

    end
  end
end