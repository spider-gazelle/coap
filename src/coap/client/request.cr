require "../../coap"
require "http"

class CoAP::Request < HTTP::Request
  getter message : CoAP::Message {
    message = CoAP::Message.new
    message.type = :confirmable
    message.code_class = :method
    message
  }

  def token=(value)
    message.token = value.to_slice
    value
  end

  delegate type, code_class, message_id, "message_id=", token, version, to: message

  IGNORE_HEADERS = {"Content-Length", "Origin"}

  # Backward-compatible: reads host/port/scheme from Origin header
  def to_coap
    if origin = self.headers["Origin"]?
      uri = URI.parse origin
      to_coap(uri.host.as(String), uri.port || URI.default_port(uri.scheme.as(String).downcase) || 5683, uri.scheme.as(String))
    else
      raise "no 'Origin' header provided and no host/port/scheme given"
    end
  end

  def to_coap(host : String, port : Int32, scheme : String)
    message.code_detail = CoAP::MethodCode.parse(self.method.upcase).to_u8
    options = [] of CoAP::Option

    # Build a URI for Option.from_uri
    request_uri = URI.new(scheme: scheme, host: host, port: port, path: self.path, query: self.query_params.to_s.presence)
    options.concat CoAP::Option.from_uri(request_uri)

    self.headers.each do |header, values|
      next if IGNORE_HEADERS.includes? header
      option = CoAP::Options.parse? header.gsub('-', '_')

      if option.nil?
        Log.warn { "unknown CoAP header: #{header}" }
        next
      end

      case option
      when .if_none_match?, .observe?
        values.each { |_data| options << CoAP::Option.new.of_type(option) }
      when .content_format?, .accept?
        values.each { |data| options << CoAP::Option.new.content_type(data).of_type(option) }
      when .max_age?, .size1?
        values.each { |data| options << CoAP::Option.new.max_age(data.to_u32).of_type(option) }
      when .proxy_uri?, .proxy_scheme?
        values.each { |data| options << CoAP::Option.new.string(data).of_type(option) }
      when .if_match?, .e_tag?
        values.each do |data|
          if raw = data.hexbytes?
            options << CoAP::Option.new.set_data(raw).of_type(option)
          else
            options << CoAP::Option.new.string(data).of_type(option)
          end
        end
      else
        Log.warn { "unexpected CoAP request header: #{header}" }
      end
    end

    # Read the body
    self.body.try do |data|
      data.rewind rescue nil
      buffer = IO::Memory.new
      IO.copy(data, buffer)
      message.payload_data = buffer.to_slice
    end

    message.options = options
    message
  end
end
