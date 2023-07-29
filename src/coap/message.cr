require "http"
require "bindata"
require "./option"

# coap://  default port 5683
# coaps:// default port 5684

class CoAP::Header < BinData
  endian big

  enum Type
    Confirmable    = 0
    NonConfirmable
    # Used to confirm request received and response coming later
    # or used to confirm received response
    Acknowledgement
    Reset
  end

  bit_field do
    # Should always be 1
    bits 2, :version, value: ->{ 1_u8 }
    # https://tools.ietf.org/html/rfc7252#section-4.3
    enum_bits 2, type : Type = Type::Confirmable

    bits 4, :token_length, value: ->{ token.size.to_u8 }
  end
end

# https://tools.ietf.org/html/rfc7252#section-3
class CoAP::Message < CoAP::Header
  endian big

  bit_field do
    # https://tools.ietf.org/html/rfc7252#section-12.1
    enum_bits 3, code_class : CodeClass = CodeClass::Method

    # When code_class above == Method then this indicates if it's a GET POST etc
    bits 5, :code_detail
  end

  uint16 :message_id
  bytes :token, length: ->{ token_length }

  variable_array raw_options : Option, read_next: ->{
    if remaining = io.peek
      # Are we EOF?
      if remaining.size > 0
        # are we end of options?
        if opt = raw_options[-1]?
          !opt.end_of_options?
        else
          true
        end
      else
        false
      end
    else
      false
    end
  }

  bytes :payload_data, length: ->{ io.peek.try(&.size) || 0 }

  def status_code
    (code_class.to_i * 100) + code_detail.to_i
  end

  def status_code=(value : Int | HTTP::Status | ResponseCode)
    code = case value
           when HTTP::Status::ACCEPTED
             ResponseCode::Valid.to_i
           when HTTP::Status::CONTINUE
             ResponseCode::Continue.to_i
           else
             value.to_i
           end

    self.code_class = CodeClass.from_value(code // 100)
    self.code_detail = (code % 100).to_u8
    value
  end

  # These do actually differ slightly from the HTTP originals
  # https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#response-codes
  def status
    ResponseCode.from_value(status_code)
  end

  def status=(value : Int | HTTP::Status | ResponseCode)
    self.status_code = value
  end

  def success?
    code_class.success?
  end

  def method
    raise "expected Method, not #{code_class}" unless code_class.method?
    MethodCode.from_value(code_detail)
  end

  def method=(verb : MethodCode)
    self.code_class = CodeClass::Method
    self.code_detail = verb.to_u8
    verb
  end

  getter uri : URI do
    host = nil
    port = nil
    path = "/"

    query = URI::Params.build do |param|
      self.options.each do |option|
        case option.type
        when .uri_path?
          path = "#{path}#{URI.encode_path_segment(option.string)}/"
        when .uri_query?
          parts = option.string.split("=", 2)
          param.add parts[0], parts[1]?
        when .uri_host?
          host = option.string
        when .uri_port?
          port = option.uri_port
        end
      end
    end

    URI.new(
      scheme: "coap",
      host: host,
      port: port.try(&.to_i32),
      path: path,
      query: query
    )
  end

  def uri=(uri : URI)
    options = [] of CoAP::Option
    options << CoAP::Option.new.string(uri.host.as(String)).type(CoAP::Options::Uri_Host) if uri.host.presence
    options << CoAP::Option.new.uri_port(uri.port.as(Int32)) if uri.port
    options.concat uri.path.split('/').compact_map { |segment| CoAP::Option.new.string(segment).type(CoAP::Options::Uri_Path) if segment.presence }
    uri.query_params.each do |param, value|
      if value.presence
        param = "#{param}=#{value}"
      end
      options << CoAP::Option.new.string(param).type(CoAP::Options::Uri_Query)
    end
    @options = options
    self.options = options
    @uri = uri
  end

  # https://tools.ietf.org/html/rfc7252#section-12.2
  getter options : Array(Option) do
    option_number = 0
    raw_options.compact_map { |option|
      next if option.end_of_options?
      option_number += option.op_delta.to_i

      begin
        option.type Options.from_value(option_number)
      rescue error
        Log.warn(exception: error) { "unable to parse option #{option_number} with delta #{option.op_delta} data size #{option.data.size}" }
        nil
      end
    }
  end

  # allow for reasonablly flexible header parsing
  def options=(values : Enumerable(Option))
    option_number = 0

    # Exposed data
    @options = options

    # binary formatted
    self.raw_options = options.map do |option|
      # Calculate the delta
      header_int = option.type.to_i
      delta = header_int - option_number
      option_number = header_int

      # Ensure lengths are correct
      option.option_length = option.data.bytesize
      option.option_delta = delta
      option
    end

    # add the end of options flags only if required
    if self.payload_data.size > 0
      option = Option.new
      option.op_delta = 15_u8
      option.op_length = 15_u8
      self.raw_options << option
    end

    # return the options as a call to `options` would return
    options
  end
end
