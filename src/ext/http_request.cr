require "../coap"
require "http"

class HTTP::Request
  def to_coap(client)
    message = CoAP::Message.new
    message.code_class = :method
    message.code_detail = CoAP::MethodCode.parse(self.method.upcase).to_u8

    options = [CoAP::Option.new.string(client.host).type(CoAP::Options::Uri_Host)]
    options << CoAP::Option.new.uri_port(client.port).type(CoAP::Options::Uri_Port)
    options << CoAP::Option.new.string(self.path).type(CoAP::Options::Uri_Path)
    options << CoAP::Option.new.string(self.query).type(CoAP::Options::Uri_Query) if self.query.presence

    # Read the data out of the IO
    self.body.try do |data|
      # rewind if implemented
      begin
        data.rewind
      rescue
      end

      # Extract the payload
      buffer = IO::Memory.new
      buf = Bytes.new(64)
      while ((bytes = data.read(buf)) > 0)
        buffer.write(buf[0, bytes])
      end
      message.payload_data = data.to_slice
    end
  end

  def self.from_coap(message : CoAP::Message)
    # TODO::
  end
end
