module SSLScan
  module Commands
    class OnlyCertainSSL < Command

      attr_accessor :results, :sslv2, :sslv3, :tlsv1

      def initialize(opts={})
        super()
      end

    end # OnlyCertainSSL
  end # Commands
end # SSLScan