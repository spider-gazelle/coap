require "./coap"
require "./client/*"

class CoAP::Client
  getter host : String
  getter port : Int32
  getter! tls : OpenSSL::SSL::Context::Client
  alias TLSContext = OpenSSL::SSL::Context::Client | Bool | Nil

  @read_timeout : Float64?
  @write_timeout : Float64?

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

  @io : UDPSocket | OpenSSL::SSL::Socket::Client | Nil = nil

  private def io
    io = @io
    return io if io

    hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1..-2] : @host

    io = UDPSocket.new
    io.connect hostname, @port
    io.read_timeout = @read_timeout if @read_timeout
    io.write_timeout = @write_timeout if @write_timeout
    io.sync = false

    if tls = @tls
      udp_socket = io
      begin
        io = OpenSSL::SSL::Socket::Client.new(udp_socket, context: tls, sync_close: true, hostname: @host)
      rescue error
        Log.error(exception: error) { "starting dtls" }
        # don't leak the TCP socket when the SSL connection failed
        udp_socket.close
        raise error
      end
    end

    @io = io
  end

  # Sets the number of seconds to wait when reading before raising an `IO::TimeoutError`.
  #
  # ```
  # require "http/client"
  #
  # client = HTTP::Client.new("example.org")
  # client.read_timeout = 1.5
  # begin
  #   response = client.get("/")
  # rescue IO::TimeoutError
  #   puts "Timeout!"
  # end
  # ```
  def read_timeout=(read_timeout : Number)
    @read_timeout = read_timeout.to_f
  end

  # Sets the read timeout with a `Time::Span`, to wait when reading before raising an `IO::TimeoutError`.
  #
  # ```
  # require "http/client"
  #
  # client = HTTP::Client.new("example.org")
  # client.read_timeout = 5.minutes
  # begin
  #   response = client.get("/")
  # rescue IO::TimeoutError
  #   puts "Timeout!"
  # end
  # ```
  def read_timeout=(read_timeout : Time::Span)
    self.read_timeout = read_timeout.total_seconds
  end

  # Sets the write timeout - if any chunk of request is not written
  # within the number of seconds provided, `IO::TimeoutError` exception is raised.
  def write_timeout=(write_timeout : Number)
    @write_timeout = write_timeout.to_f
  end

  # Sets the write timeout - if any chunk of request is not written
  # within the provided `Time::Span`,  `IO::TimeoutError` exception is raised.
  def write_timeout=(write_timeout : Time::Span)
    self.write_timeout = write_timeout.total_seconds
  end

  @message_id : UInt16 = rand(UInt16::MAX).to_u16

  private def next_message_id
    @message_id += rand(10).to_u16
  rescue OverflowError
    @message_id = rand(UInt16::MAX).to_u16
  ensure
    @message_id
  end

  @token : UInt8 = rand(UInt8::MAX).to_u8

  private def next_token
    @token += rand(5).to_u8
  rescue OverflowError
    @token = rand(UInt8::MAX).to_u8
  ensure
    @token
  end

  # TODO:: allow this to handle multiple requests at once, including observes
  # requires channels for each message_id and a fiber for response processing
  def exec(request : CoAP::Request) : CoAP::Response
    headers = request.headers
    headers["Origin"] = "#{@tls ? "coaps" : "coap"}://#{@host}:#{@port}" unless headers["Origin"]?

    # setup tracking if at defaults
    request.message_id = next_message_id if request.message_id == 0_u16
    request.token = Bytes[next_token] if request.token.empty?

    # send the request
    message = request.to_coap
    socket = io
    socket.write_bytes(message)
    socket.flush

    # parse the response
    message = socket.read_bytes(CoAP::Message)

    # Check if we've been sent a "please wait response"
    # https://tools.ietf.org/html/rfc7252#page-107
    send_ack = false
    if message.code_class == CoAP::CodeClass::Method && message.token != request.token
      send_ack = true
      message = socket.read_bytes(CoAP::Message)
      raise "unexpected message" unless message.token == request.token
    end

    # acknowledge the response if it was delayed and confirmable
    if send_ack && message.type == CoAP::Message::Type::Confirmable
      ack = CoAP::Message.new
      ack.type = :acknowledgement
      ack.message_id = message.message_id
      socket.write_bytes(ack)
      socket.flush
    end

    CoAP::Response.from_coap(message)
  end
end
