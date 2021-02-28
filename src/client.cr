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
             OpenSSL::SSL::Context::Client.new(::LibSSL.dtls_method)
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

  private def io
    hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1..-2] : @host

    io = UDPSocket.new
    io.connect hostname, @port
    io.sync = false

    if tls = @tls
      tcp_socket = io
      begin
        io = OpenSSL::SSL::Socket::Client.new(tcp_socket, context: tls, sync_close: true, hostname: @host)
      rescue exc
        # don't leak the TCP socket when the SSL connection failed
        tcp_socket.close
        raise exc
      end
    end

    io
  end

  def exec(request : CoAP::Request) : CoAP::Response
    # TODO:: add port where required
    request.headers["Origin"] = "#{@tls ? "coaps" : "coap"}://#{@host}"

    # TODO:: proper message IDs
    request.message_id = 15901_u16
    message = request.to_coap
    socket = io
    socket.write_bytes(message)
    socket.flush

    # TODO:: timeouts
    message = socket.read_bytes(CoAP::Message)
    CoAP::Response.from_coap(message)
  end
end
