require "./coap"
require "./client/*"

class CoAP::Client
  getter host : String
  getter port : Int32
  getter! tls : OpenSSL::SSL::Context::Client
  alias TLSContext = OpenSSL::SSL::Context::Client | Bool | Nil

  # default CoAP timeout
  getter read_timeout : Float64 = 3.0

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
  @io : CoAP::IOWrapper? = nil

  def io=(transport : IO)
    @mutex.synchronize do
      close if @io
      @io = CoAP::IOWrapper.new(transport, self).start
    end
    transport
  end

  private def io : CoAP::IOWrapper
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

      @io = client_io = CoAP::IOWrapper.new(io, self).start
      client_io
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
    Log.trace { "transmitting request #{message.message_id}, token #{message.token.hexstring}, type #{message.type}, class #{message.code_class}" }

    if !message.token.empty? && message.type.confirmable?
      @mutex.synchronize {
        response = ResponseHandler.new message.message_id, @read_timeout.seconds.from_now
        @tokens[message.token] = response
        @messages[message.message_id] = message.token
      }
    end

    io.transmit(message)
    response
  end

  def process_message(message : CoAP::Message)
    Log.trace { "received message #{message.message_id}, token #{message.token.hexstring}\n#{message.inspect}" }

    # Check we were expecting this message
    token_id = @mutex.synchronize { @messages.delete(message.message_id) }
    Log.trace { "message id #{message.message_id} #{token_id ? "expected" : "unexpected"}" }

    if !message.token.empty?
      # if it has a token then we probably were expecting this
      if responder = @mutex.synchronize { @tokens[message.token]? }
        Log.trace { "token lookup success for #{message.token.hexstring}" }
        responder.send(message)
      else
        Log.info { "CoAP message #{message.message_id}, token #{message.token.hexstring} possibly received after timeout" }
      end

      if message.type.confirmable?
        Log.trace { "message #{message.message_id} required acknowledgement" }

        ack = CoAP::Message.new
        ack.type = :acknowledgement
        ack.message_id = message.message_id
        transmit(ack)
      end
    elsif token_id && message.code_class.method?
      Log.trace { "message expected, however data not available yet" }

      # we were tracking the message ID so probably the service is taking time to return the result
      # we want to increase the timeout for the token tracking https://tools.ietf.org/html/rfc7252#page-107
      @mutex.synchronize {
        if responder = @tokens[token_id]?
          Log.trace { "setting #{token_id.hexstring} timeout to #{@read_timeout * 5}" }
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

  def close : Nil
    @mutex.synchronize {
      iow = @io
      iow.close if iow && !iow.closed?
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

  def finalize
    Log.trace { "client GC'd" }

    @io.try(&.close)

    # close all the channels
    @mutex.synchronize {
      @io = nil
      @tokens.each_value(&.close)
    }
  end

  def check_for_timeouts
    time = Time.utc

    @mutex.synchronize {
      @tokens.reject! do |bytes, responder|
        if responder.timeout < time
          @messages.delete(responder.message_id)
          responder.close
          Log.trace {
            if responder.processed > 0
              "closing channel for token '#{bytes.hexstring}', processed #{responder.processed} messages"
            else
              "message #{responder.message_id} timeout waiting for token '#{bytes.hexstring}' data"
            end
          }
          true
        end
      end
    }
  end
end
