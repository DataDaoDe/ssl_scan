module SSLScan
  module Commands
    class Command
      attr_accessor :results, :options, :stream, :errors
      include FastGettext::Translation

      def initialize(results=[], stream=nil)
        @results = results
        @errors  = []
        @stream  = stream || STDOUT
      end

      def execute
        raise "Implement"
      end

      # Display Methods
      def write_header(host, port=443)
        stream.printf _("\nTesting SSL server %{host} on port %{port}\n") % { host: host, port: port }
      end

      def write_preferred_ciphers(scanner)
        stream.printf _("\nServer Preferred Cipher(s)\n")
        ciphers = scanner.get_preferred_ciphers
        ciphers.each do |c|
          if c.length > 1 && !c[1].empty?
            stream.printf("%12s %10s %s\n", c[0], "#{c[1][3]} bits", c[1][0])
          end
        end
        stream.printf("\n")
      end

      def write_ciphers(scanner=nil)
        stream.printf _("\nSupported Server Cipher(s):\n")

        sslv = options.only_ssl2 || options.only_ssl3 || options.only_tls1 || false
        
        if sslv
          scanner.scan_ssl_version(sslv) do |ssl_version, cipher_name, alg_length, status|
            unless options.no_failed && status == :failed
              stream.printf("%12s %10s %10s %s\n", status, ssl_version, "#{alg_length} bits",  cipher_name)
            end
          end
        else
          scanner.scan do |ssl_version, cipher_name, alg_length, status|
            unless options.no_failed && status == :failed
              stream.printf "%12s %10s %10s %s\n", status, ssl_version, "#{alg_length} bits",  cipher_name
            end
          end
        end
        stream.printf("\n")
        scanner
      end

    end
  end
end
