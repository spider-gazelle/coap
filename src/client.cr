require "./coap"
require "./client/*"

class CoAP::Client
  getter host : String
  getter port : Int32
  getter! tls : OpenSSL::SSL::Context::Client
  alias TLSContext = OpenSSL::SSL::Context::Client | Bool | Nil

  # default CoAP timeout
  @read_timeout : Float64 = 2.0

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

  @mutex = Mutex.new(:reentrant)
  @io : IO | Nil = nil

  def io=(transport : IO)
    @mutex.synchronize { @io = transport }
  end

  private def io : IO
    io = @io
    return io if io

    @mutex.synchronize {
      io = @io
      return io if io

      hostname = @host.starts_with?('[') && @host.ends_with?(']') ? @host[1..-2] : @host

      io = UDPSocket.new
      io.connect hostname, @port
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
      spawn { consume_io }
      spawn { perform_timeouts }
      io
    }
  end

  # Sets the number of seconds to wait when reading before raising an `IO::TimeoutError`.
  def read_timeout=(read_timeout : Number)
    @read_timeout = read_timeout.to_f
  end

  # Sets the read timeout with a `Time::Span`, to wait when reading before raising an `IO::TimeoutError`.
  def read_timeout=(read_timeout : Time::Span)
    self.read_timeout = read_timeout.total_seconds
  end

  @message_id : UInt16 = rand(UInt16::MAX).to_u16

  private def next_message_id
    @message_id += rand(10).to_u16
  rescue OverflowError
    @message_id = rand(10).to_u16
  ensure
    @message_id
  end

  @token : UInt8 = rand(UInt8::MAX).to_u8

  private def next_token
    @token += rand(5).to_u8
  rescue OverflowError
    @token = rand(5).to_u8
  ensure
    @token
  end

  def before_request(&callback : CoAP::Request ->)
    before_request = @before_request ||= [] of (CoAP::Request ->)
    before_request << callback
  end

  def before_transmit(&callback : CoAP::Message ->)
    before_transmit = @before_transmit ||= [] of (CoAP::Message ->)
    before_transmit << callback
  end

  # TODO:: allow this to handle multiple requests at once, including observes
  # requires channels for each message_id and a fiber for response processing
  def exec(request : CoAP::Request) : CoAP::ResponseHandler?
    @before_request.try &.each &.call(request)

    headers = request.headers
    headers["Origin"] = "#{@tls ? "coaps" : "coap"}://#{@host}:#{@port}" unless headers["Origin"]?

    # send the request
    message = request.to_coap
    @before_transmit.try &.each &.call(message)

    # setup tracking if at defaults
    message.message_id = next_message_id if message.message_id == 0_u16
    message.token = Bytes[next_token] if message.token.empty? && message.type.confirmable?

    transmit(message)
  end

  def exec!(request : CoAP::Request) : CoAP::ResponseHandler
    exec(request).not_nil!
  end

  # message_id => token id
  @messages = {} of UInt16 => Bytes

  # token id => message + timeout
  @tokens = {} of Bytes => ResponseHandler

  protected def transmit(message)
    response = nil
    @mutex.synchronize {
      if !message.token.empty? && message.type.confirmable?
        response = ResponseHandler.new message.message_id, @read_timeout.seconds.from_now
        @tokens[message.token] = response
        @messages[message.message_id] = message.token
      end

      socket = io
      socket.write_bytes(message)
      socket.flush
    }
    response
  end

  private def consume_io
    if socket = @io
      while !socket.closed?
        message = socket.read_bytes(CoAP::Message)

        # Check we were expecting this message
        token_id = @mutex.synchronize { @messages.delete(message.message_id) }

        if !message.token.empty?
          # if it has a token then we probably were expecting this
          if responder = @mutex.synchronize { @tokens[message.token]? }
            responder.send(message)
          else
            Log.info { "CoAP message #{message.message_id}, token #{message.token.hexstring} possibly received after timeout" }
          end

          if message.type.confirmable?
            ack = CoAP::Message.new
            ack.type = :acknowledgement
            ack.message_id = message.message_id

            @mutex.synchronize {
              socket.write_bytes(ack)
              socket.flush
            }
          end
        elsif token_id && message.code_class.method?
          # we were tracking the message ID so probably the service is taking time to return the result
          # we want to increase the timeout for the token tracking https://tools.ietf.org/html/rfc7252#page-107
          @mutex.synchronize {
            if responder = @tokens[token_id]?
              responder.timeout = (@read_timeout * 5).seconds.from_now
            else
              Log.info { "tracked CoAP message #{message.message_id}, token #{token_id}  received after timeout" }
            end
          }
        else
          # we were not expecting this message
          Log.info { "received unexpected CoAP message #{message.type} #{message.message_id}" }
        end
      end
    end
  rescue error
    Log.error(exception: error) { "error consuming IO" }
  ensure
    close
  end

  def close : Nil
    @mutex.synchronize {
      @io.try(&.close)
      @io = nil

      # close all the channels
      @tokens.each_value(&.close)
      @tokens.clear
      @messages.clear
    }
  end

  def closed?
    @io.try(&.closed?) || true
  end

  def perform_timeouts
    # TODO::
  end
end
