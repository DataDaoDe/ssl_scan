# -*- coding: binary -*-

###
#
# This class provides methods for interacting with a TCP server.  It
# implements the SSLScan::IO::StreamServer interface.
#
###
module  SSLScan::Socket::TcpServer

  include SSLScan::Socket
  include SSLScan::IO::StreamServer

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the server using the supplied hash.
  #
  def self.create(hash = {})
    hash['Proto'] = 'tcp'
    hash['Server'] = true
    self.create_param(SSLScan::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base class' creation method that automatically sets
  # the parameter's protocol to TCP and sets the server flag to true.
  #
  def self.create_param(param)
    param.proto  = 'tcp'
    param.server = true
    SSLScan::Socket.create_param(param)
  end

  #
  # Accepts a child connection.
  #
  def accept(opts = {})
    t = super()

    # jRuby compatibility
    if t.respond_to?('[]')
      t = t[0]
    end

    if (t)
      t.extend(SSLScan::Socket::Tcp)
      t.context = self.context

      pn = t.getpeername

      t.peerhost = pn[1]
      t.peerport = pn[2]
    end

    t
  end

end

