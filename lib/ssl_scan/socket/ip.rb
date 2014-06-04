# -*- coding: binary -*-
require 'ssl_scan/socket'

###
#
# This class provides methods for interacting with a IP socket.
#
###
module SSLScan::Socket::Ip

  include SSLScan::Socket

  ##
  #
  # Factory
  #
  ##

  #
  # Creates the client using the supplied hash.
  #
  def self.create(hash = {})
    hash['Proto'] = 'ip'
    self.create_param(SSLScan::Socket::Parameters.from_hash(hash))
  end

  #
  # Wrapper around the base socket class' creation method that automatically
  # sets the parameter's protocol to IP.
  #
  def self.create_param(param)
    param.proto = 'ip'
    SSLScan::Socket.create_param(param)
  end

  ##
  #
  # IP connected state methods
  #
  ##

  #
  # Write the supplied datagram to the connected IP socket.
  #
  def write(gram)
    raise RuntimeError, "IP sockets must use sendto(), not write()"
  end

  alias put write

  #
  # Read a datagram from the IP socket.
  #
  def read(length = 65535)
    raise RuntimeError, "IP sockets must use recvfrom(), not read()"
  end

  ##
  #
  # IP non-connected state methods
  #
  ##

  #
  # Sends a datagram to the supplied host:port with optional flags.
  #
  def sendto(gram, peerhost, flags = 0)
    dest = ::Socket.pack_sockaddr_in(0, peerhost)

    # Some BSDs require byteswap for len and offset
    if(
      SSLScan::Compat.is_freebsd or
      SSLScan::Compat.is_netbsd or
      SSLScan::Compat.is_bsdi or
      SSLScan::Compat.is_macosx
      )
      gram=gram.dup
      gram[2,2]=gram[2,2].unpack("n").pack("s")
      gram[6,2]=gram[6,2].unpack("n").pack("s")
    end

    begin
      send(gram, flags, dest)
    rescue  ::Errno::EHOSTUNREACH,::Errno::ENETDOWN,::Errno::ENETUNREACH,::Errno::ENETRESET,::Errno::EHOSTDOWN,::Errno::EACCES,::Errno::EINVAL,::Errno::EADDRNOTAVAIL
      return nil
    end

  end

  #
  # Receives a datagram and returns the data and host of the requestor
  # as [ data, host ].
  #
  def recvfrom(length = 65535, timeout=def_read_timeout)
    begin
      if ((rv = ::IO.select([ fd ], nil, nil, timeout)) and
          (rv[0]) and (rv[0][0] == fd)
         )
          data, saddr    = super(length)
          af, host       = SSLScan::Socket.from_sockaddr(saddr)

          return [ data, host ]
      else
        return [ '', nil ]
      end
    rescue Exception
      return [ '', nil ]
    end
  end

  #
  # Calls recvfrom and only returns the data
  #
  def get(timeout=nil)
    data, saddr = recvfrom(65535, timeout)
    return data
  end

  #
  # The default number of seconds to wait for a read operation to timeout.
  #
  def def_read_timeout
    10
  end

  def type?
    return 'ip'
  end

end

