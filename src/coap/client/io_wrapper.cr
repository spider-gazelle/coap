require "../../coap"
require "weak_ref"

# This class exists to monitor the IO for the lifetime of the client
# WeakRef ensures we can cleanup the spawned threads once GC occurs
class CoAP::IOWrapper
  def initialize(@io : IO, client : CoAP::Client)
    @client = WeakRef.new(client)
    @transmit = Channel(CoAP::Message).new
    @received = Channel(CoAP::Message).new
  end

  @client : WeakRef(CoAP::Client)

  def close
    @transmit.close
    @received.close
    @io.close
    @client.value.try &.close
  end

  def closed?
    @io.closed?
  end

  def start
    spawn { process_io }
    self
  end

  def transmit(message : CoAP::Message)
    @transmit.send(message)
  end

  private def process_io
    Log.trace { "started IO processing" }

    spawn(same_thread: true) { read_messages }
    loop do
      break unless client_exists?

      select
      when output = @transmit.receive
        @io.write_bytes(output)
        @io.flush
      when input = @received.receive
        client_process_message(input)
      when timeout(get_timeout)
        client_check_for_timeouts
      end
    end
  rescue IO::Error | Channel::ClosedError
  rescue error
    Log.error(exception: error) { "error processing IO" }
  ensure
    Log.trace { "stopped processing IO" }
    close
  end

  private def client_exists?
    !@client.value.nil?
  end

  private def client_process_message(input)
    @client.value.try(&.process_message(input))
  end

  private def client_check_for_timeouts
    @client.value.try(&.check_for_timeouts)
  end

  private def get_timeout : Time::Span
    @client.value.try(&.read_timeout.seconds) || 1.second
  end

  private def read_messages : Nil
    Log.trace { "started reading messages" }
    while client_exists? && !@io.closed?
      @received.send @io.read_bytes(CoAP::Message)
    end
  rescue IO::Error
  rescue error
    Log.error(exception: error) { "error consuming IO" } unless error.cause.is_a?(IO::Error)
  ensure
    Log.trace { "stopped reading messages" }
    close
  end
end
