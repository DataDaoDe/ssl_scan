# SSLScan

SSLScan is an extraction of the the sslscan module from the [metasploit-framework](https://github.com/rapid7/metasploit-framework). It provides lower level tools for testing sslv2/3 and tls connections with servers.

However, the sslscan module in metasploit is mainly used for finding weakpoints in SSL armor. What this gem does is adapt some of that functionality to provide ways for the user to debug ssl connections and conversely make ssl connections work - not discover weakpoints. For instance, maybe in your client you are attempting to use SSLv3 to connect to a server and throwing exceptions, you could use this gem to find out that SSLv3 is not supported by the peer and use TLSv1 with the servers preferred cipher instead to allow your client application to still work.

In addition to the goals stated above, this library also provides a pure ruby implementation for [sslscan](http://sourceforge.net/projects/sslscan/), with some added nicities.


## Installation

Add this line to your application's Gemfile:

    gem 'sslscan'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install sslscan

## Usage

```ruby

require 'ssl_scan'
scanner = SSLScan::Scanner.new('example.com')

# returns an SSLScan::Result object containing a list of accepted/rejected ciphers, peer_supported ssl versions, etc.
scanner.scan

# show the ciphers which the server prefers
scanner.get_preferred_ciphers

# You can also pass a block to the scan function to be able to do things 
# like write to a socket stream and get some feedback to your users
# - status can be either accepted or rejected for a particular cipher
scanner.scan do |ssl_version, cipher, key_length, status, cert|
  # ...
end
```

## Contributing

1. Fork it ( http://github.com/<my-github-username>/sslscan/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
