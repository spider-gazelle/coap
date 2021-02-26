require "../coap"
require "http"

class CoAP::Request < HTTP::Request
  getter message : CoAP::Message = CoAP::Message.new

  def token=(value)
    message.token = value.to_slice
    value
  end

  delegate message_id, "message_id=", token, version, to: message

  def to_coap(message_type : CoAP::Message::Type = :confirmable)
    message.type = message_type
    message.code_class = :method
    message.code_detail = CoAP::MethodCode.parse(self.method.upcase).to_u8

    options = [CoAP::Option.new.string(self.path).type(CoAP::Options::Uri_Path)]
    options << CoAP::Option.new.string(self.query.not_nil!).type(CoAP::Options::Uri_Query) if self.query.presence

    if origin = self.headers.delete("Origin")
      uri = URI.parse origin
      port = uri.port || URI.default_port(uri.scheme.not_nil!.downcase) || raise("unable to infer CoAP port for #{origin}")

      options << CoAP::Option.new.string(uri.host.not_nil!).type(CoAP::Options::Uri_Host)
      options << CoAP::Option.new.uri_port(port).type(CoAP::Options::Uri_Port)
    else
      raise "no 'Origin' header provided"
    end

    self.headers.each do |header, values|
      option = CoAP::Options.parse? header.gsub('-', '_')

      if option.nil?
        Log.warn { "unknown CoAP header: #{header}" }
        next
      end

      case option
      when .if_none_match?, .observe?
        # empty
        values.each { |data| options << CoAP::Option.new.type(option) }
      when .content_format?, .accept?
        values.each { |data| options << CoAP::Option.new.content_type(data).type(option) }
      when .max_age?, .size1?
        values.each { |data| options << CoAP::Option.new.max_age(data.to_u32).type(option) }
      when .proxy_uri?, .proxy_scheme?, .if_match?, .e_tag?
        values.each { |data| options << CoAP::Option.new.string(data).type(option) }
      else
        Log.warn { "unexpected CoAP request header: #{header}" }
      end
    end

    message.options = options

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
      message.payload_data = buffer.to_slice
    end

    message
  end
end
