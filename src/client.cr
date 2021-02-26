require "./coap"
require "./client/*"

class CoAP::Client
  getter host : String
  getter port : Int32
  getter! tls : OpenSSL::SSL::Context::Client
  alias TLSContext = OpenSSL::SSL::Context::Client | Bool | Nil

  @read_timeout : Float64?

  def initialize(@host : String, port = nil, tls : TLSContext = nil)
    @tls = case tls
             when true
               # TODO:: needs to be DTLS enabled
               OpenSSL::SSL::Context::Client.new
             when OpenSSL::SSL::Context::Client
               tls
             when false, nil
               nil
             end
    @port = (port || (@tls ? 5684 : 5683)).to_i
  end

  def self.new(uri : URI, tls : TLSContext = nil)
    scheme = uri.scheme.not_nil!.downcase
    port = uri.port || URI.default_port(scheme) || raise("unable to infer CoAP port for #{uri}")
    raise "TLS required for coaps" if tls == false && scheme == "coaps"
    self.new(uri.host.not_nil!, port, tls)
  end
end
