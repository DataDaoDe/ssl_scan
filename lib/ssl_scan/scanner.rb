module SSLScan

class Scanner

  attr_accessor :context
  attr_accessor :host
  attr_accessor :port
  attr_accessor :timeout

  attr_reader :supported_versions
  attr_reader :peer_supported_versions
  attr_reader :results
  attr_reader :sslv2

  # Initializes the scanner object
  # @param host [String] IP address or hostname to scan
  # @param port [Fixnum] Port number to scan, default: 443
  # @param timeout [Fixnum] Timeout for connections, in seconds. default: 5
  # @raise [StandardError] Raised when the configuration is invalid
  def initialize(host,port = 443,context = {},timeout=5)
    @host       = host
    @port       = port
    @timeout    = timeout
    @context    = context
    if check_opensslv2 == true
      @supported_versions = [:SSLv2, :SSLv3, :TLSv1]
      @sslv2 = true
    else
      @supported_versions = [:SSLv3, :TLSv1]
      @sslv2 = false
    end
    @peer_supported_versions = []
    raise StandardError, "The scanner configuration is invalid" unless valid?
  end

  # Checks whether the scanner option has a valid configuration
  # @return [Boolean] True or False, the configuration is valid.
  def valid?
    begin
      @host = SSLScan::Socket.getaddress(@host, true)
    rescue
      return false
    end
    return false unless @port.kind_of? Fixnum
    return false unless @port >= 0 and @port <= 65535
    return false unless @timeout.kind_of? Fixnum
    return true
  end

  # Initiate the Scan against the target. Will test each cipher one at a time.
  # @return [Result] object containing the details of the scan
  def scan(&block)
    scan_result = SSLScan::Result.new
    scan_result.openssl_sslv2 = sslv2
    # If we can't get any SSL connection, then don't bother testing
    # individual ciphers.
    
    @supported_versions.each do |ssl_version|
      sslctx = OpenSSL::SSL::SSLContext.new(ssl_version)
      sslctx.ciphers.each do |cipher_name, ssl_ver, key_length, alg_length|
        status = test_cipher(ssl_version, cipher_name)
        scan_result.add_cipher(ssl_version, cipher_name, key_length, status)
        if status == :accepted and scan_result.cert.nil?
          scan_result.cert = get_cert(ssl_version, cipher_name)
        end

        if block_given?
          yield(ssl_version, cipher_name, alg_length, status, scan_result.cert)
        end
        
      end
    end
    @peer_supported_versions = [].tap do |psv|
      psv << :SSLv2 if scan_result.supports_sslv2?
      psv << :SSLv3 if scan_result.supports_sslv3?
      psv << :TLSv1 if scan_result.supports_tlsv1?
    end
    @results = scan_result
    scan_result
  end

  def scan_ssl_version(ssl_version, &block)
    scan_result = SSLScan::Result.new
    scan_result.openssl_sslv2 = sslv2
    # If we can't get any SSL connection, then don't bother testing
    # individual ciphers.
    if ([:rejected, :failed].include?(test_ssl) and [:rejected, :failed].include?(test_tls)) or !@supported_versions.include?(ssl_version)
      return scan_result
    end

    sslctx = OpenSSL::SSL::SSLContext.new(ssl_version)
    sslctx.ciphers.each do |cipher_name, ssl_ver, key_length, alg_length|

      status = test_cipher(ssl_version, cipher_name)
      scan_result.add_cipher(ssl_version, cipher_name, key_length, status)
      if status == :accepted and scan_result.cert.nil?
        scan_result.cert = get_cert(ssl_version, cipher_name)
      end

      if block_given?
        yield(ssl_version, cipher_name, alg_length, status, scan_result.cert)
      end
      
    end
    @results = scan_result
    scan_result
  end

  def get_preferred_ciphers
    ssl_versions = {}.tap do |v|
      @supported_versions.each { |sv| v[sv] = [] } 
    end

    ssl_versions.keys.each do |ssl_version|
      begin
        scan_client = SSLScan::Socket::Tcp.create(
          'Context'    => @context,
          'PeerHost'   => @host,
          'PeerPort'   => @port,
          'SSL'        => true,
          'SSLVersion' => ssl_version,
          'Timeout'    => @timeout
        )
        ssl_versions[ssl_version] = scan_client.cipher
      rescue => ex
        ssl_versions.delete(ssl_version)
      end
    end
    ssl_versions
  end


  def get_first_valid_cert
    scan_result = SSLScan::Result.new
    scan_result.openssl_sslv2 = sslv2
    @supported_versions.each do |ssl_version|
      begin
        scan_client = SSLScan::Socket::Tcp.create(
          'Context'    => @context,
          'PeerHost'   => @host,
          'PeerPort'   => @port,
          'SSL'        => true,
          'SSLVersion' => ssl_version,
          'Timeout'    => @timeout
        )
        cipher_name = scan_client.cipher[0]
        key_length  = scan_client.cipher[3]
        status = test_cipher(ssl_version, cipher_name)
        scan_result.add_cipher(ssl_version, cipher_name, key_length, status)
        if status == :accepted and scan_result.cert.nil?
          scan_result.cert = get_cert(ssl_version, cipher_name)
          break
        end
      rescue => ex
        # noop
      end
    end
    @results = scan_result
    scan_result
  end

  def test_ssl
    begin
      scan_client = SSLScan::Socket::Tcp.create(
        'Context'    => @context,
        'PeerHost'   => @host,
        'PeerPort'   => @port,
        'SSL'        => true,
        'SSLVersion' => :SSLv23,
        'Timeout'    => @timeout
      )
    rescue ::Exception => e
      if e.kind_of?(Errno::ECONNRESET)
        return :failed
      else
        return :rejected
      end
    ensure
      if scan_client
        scan_client.close
      end
    end
    return :accepted
  end

  def test_tls
    begin
      scan_client = SSLScan::Socket::Tcp.create(
        'Context'    => @context,
        'PeerHost'   => @host,
        'PeerPort'   => @port,
        'SSL'        => true,
        'SSLVersion' => :TLSv1,
        'Timeout'    => @timeout
      )
    rescue ::Exception => e
      if e.kind_of?(Errno::ECONNRESET)
        return :failed
      else
        return :rejected
      end
    ensure
      if scan_client
        scan_client.close
      end
    end
    return :accepted
  end

  # Tests the specified SSL Version and Cipher against the configured target
  # @param ssl_version [Symbol] The SSL version to use (:SSLv2,  :SSLv3, :TLSv1)
  # @param cipher [String] The SSL Cipher to use
  # @return [Symbol] Either :accepted or :rejected
  def test_cipher(ssl_version, cipher)
    validate_params(ssl_version,cipher)
    begin
      scan_client = SSLScan::Socket::Tcp.create(
        'Context'    => @context,
        'PeerHost'   => @host,
        'PeerPort'   => @port,
        'SSL'        => true,
        'SSLVersion' => ssl_version,
        'SSLCipher'  => cipher,
        'Timeout'    => @timeout
      )
    rescue ::Exception => e
      if e.kind_of?(Errno::ECONNRESET)
        return :failed
      else
        return :rejected
      end
    ensure
      if scan_client
        scan_client.close
      end
    end

    return :accepted
  end

  # Retrieve the X509 Cert from the target service,
  # @param ssl_version [Symbol] The SSL version to use (:SSLv2,  :SSLv3, :TLSv1)
  # @param cipher [String] The SSL Cipher to use
  # @return [OpenSSL::X509::Certificate] if the certificate was retrieved
  # @return [Nil] if the cert couldn't be retrieved
  def get_cert(ssl_version, cipher)
    validate_params(ssl_version, cipher)
    begin
      scan_client = SSLScan::Socket::Tcp.create(
        'PeerHost'   => @host,
        'PeerPort'   => @port,
        'SSL'        => true,
        'SSLVersion' => ssl_version,
        'SSLCipher'  => cipher,
        'Timeout'    => @timeout
      )
      cert = scan_client.peer_cert
      if cert.kind_of? OpenSSL::X509::Certificate
        return cert
      else
        return nil
      end
    rescue ::Exception => e
      return nil
    ensure
      if scan_client
        scan_client.close
      end
    end
  end


  protected

  # Validates that the SSL Version and Cipher are valid both seperately and
  # together as part of an SSL Context.
  # @param ssl_version [Symbol] The SSL version to use (:SSLv2,  :SSLv3, :TLSv1)
  # @param cipher [String] The SSL Cipher to use
  # @raise [StandardError] If an invalid or unsupported SSL Version was supplied
  # @raise [StandardError] If the cipher is not valid for that version of SSL
  def validate_params(ssl_version, cipher)
    raise StandardError, "The scanner configuration is invalid" unless valid?
    unless @supported_versions.include? ssl_version
      raise StandardError, "SSL Version must be one of: #{@supported_versions.to_s}"
    end
    if ssl_version == :SSLv2 and sslv2 == false
      raise StandardError, "Your OS hates freedom! Your OpenSSL libs are compiled without SSLv2 support!"
    else
      unless OpenSSL::SSL::SSLContext.new(ssl_version).ciphers.flatten.include? cipher
        raise StandardError, "Must be a valid SSL Cipher for #{ssl_version}!"
      end
    end
  end

  def check_opensslv2
    begin
      OpenSSL::SSL::SSLContext.new(:SSLv2)
    rescue
      return false
    end
    return true
  end

end
end
