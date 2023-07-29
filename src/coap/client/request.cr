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

  IGNORE_HEADERS = {"Content-Length"}

  # ameba:disable Metrics/CyclomaticComplexity
  def to_coap
    message.code_detail = CoAP::MethodCode.parse(self.method.upcase).to_u8
    options = [] of CoAP::Option

    # Host and port
    if origin = self.headers.delete("Origin")
      uri = URI.parse origin
      default_port = URI.default_port(uri.scheme.as(String).downcase)
      port = uri.port || default_port || raise("unable to infer CoAP port for #{origin}")

      options << CoAP::Option.new.string(uri.host.as(String)).type(CoAP::Options::Uri_Host)
      options << CoAP::Option.new.uri_port(port) unless port == default_port
    else
      raise "no 'Origin' header provided"
    end

    # query path
    options.concat self.path.split('/').compact_map { |segment| CoAP::Option.new.string(segment).type(CoAP::Options::Uri_Path) if segment.presence }

    # query params
    self.query_params.each do |param, value|
      if value.presence
        param = "#{param}=#{value}"
      end
      options << CoAP::Option.new.string(param).type(CoAP::Options::Uri_Query)
    end

    self.headers.each do |header, values|
      next if IGNORE_HEADERS.includes? header
      option = CoAP::Options.parse? header.gsub('-', '_')

      if option.nil?
        Log.warn { "unknown CoAP header: #{header}" }
        next
      end

      case option
      when .if_none_match?, .observe?
        # empty
        values.each { |_data| options << CoAP::Option.new.type(option) }
      when .content_format?, .accept?
        values.each { |data| options << CoAP::Option.new.content_type(data).type(option) }
      when .max_age?, .size1?
        values.each { |data| options << CoAP::Option.new.max_age(data.to_u32).type(option) }
      when .proxy_uri?, .proxy_scheme?
        values.each { |data| options << CoAP::Option.new.string(data).type(option) }
      when .if_match?, .e_tag?
        values.each do |data|
          if raw = data.hexbytes?
            options << CoAP::Option.new.data(raw).type(option)
          else
            options << CoAP::Option.new.string(data).type(option)
          end
        end
      else
        Log.warn { "unexpected CoAP request header: #{header}" }
      end
    end

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
      while (bytes = data.read(buf)) > 0
        buffer.write(buf[0, bytes])
      end
      message.payload_data = buffer.to_slice
    end

    # Set options after payload is configured
    # as we need to know if we need the "end of options" option flag
    message.options = options

    message
  end
end
