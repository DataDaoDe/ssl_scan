require 'spec_helper'

describe SSLScan::Scanner do

  subject { SSLScan::Scanner.new('google.com', 443) }

  # attr_accessors
  it { should respond_to(:host) }
  it { should respond_to(:port) }
  it { should respond_to(:timeout) }
  it { should respond_to(:context) }

  # attr_readers
  it { should respond_to(:supported_versions) }
  it { should respond_to(:peer_supported_versions) }
  it { should respond_to(:results) }
  it { should respond_to(:sslv2) }

end