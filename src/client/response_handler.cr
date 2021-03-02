require "../coap"

# Need to support multicast responses and observables
class CoAP::ResponseHandler
  def initialize(@message_id, @timeout)
    @channel = Channel(CoAP::Message).new
  end

  @channel : Channel(CoAP::Message)
  property timeout : Time
  getter message_id : UInt16
  delegate "closed?", close, to: @channel

  def send(message : CoAP::Message) : Nil
    spawn(same_thread: true) { @channel.send(message) } unless @channel.closed?
  end

  def receive : CoAP::Response
    CoAP::Response.from_coap @channel.receive
  end

  def receive? : CoAP::Response?
    if message = @channel.receive?
      CoAP::Response.from_coap message
    end
  end
end
