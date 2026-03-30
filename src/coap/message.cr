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
    bits 2, :version, value: -> { 1_u8 }
    # https://tools.ietf.org/html/rfc7252#section-4.3
    bits 2, type : Type = Type::Confirmable

    bits 4, :token_length, value: -> { token.size.to_u8 }
  end
end

# https://tools.ietf.org/html/rfc7252#section-3
class CoAP::Message < CoAP::Header
  endian big

  bit_field do
    # https://tools.ietf.org/html/rfc7252#section-12.1
    bits 3, code_class : CodeClass = CodeClass::Method

    # When code_class above == Method then this indicates if it's a GET POST etc
    bits 5, :code_detail
  end

  field message_id : UInt16
  field token : Bytes, length: -> { token_length }

  field raw_options : Array(Option), read_next: -> {
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

  field payload_data : Bytes, length: -> { io.peek.try(&.size) || 0 }

  # Eagerly parse raw_options into typed options after reading from wire
  after_deserialize { @options = parse_options }

  # Recompute raw_options from typed options before writing to wire
  before_serialize { prepare_options_for_write }

  def status_code
    (code_class.to_i * 100) + code_detail.to_i
  end

  def status_code=(value : Int | HTTP::Status | ResponseCode)
    code = case value
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
    segments = [] of String

    query = URI::Params.build do |param|
      self.options.each do |option|
        case option.type
        when .uri_path?
          segments << URI.encode_path_segment(option.string)
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

    path = segments.empty? ? "/" : "/#{segments.join('/')}"

    URI.new(
      scheme: "coap",
      host: host,
      port: port.try(&.to_i32),
      path: path,
      query: query
    )
  end

  def uri=(uri : URI)
    self.options = Option.from_uri(uri)
    @uri = uri
  end

  # https://tools.ietf.org/html/rfc7252#section-12.2
  property options : Array(Option) = [] of Option

  private def prepare_options_for_write
    option_number = 0

    self.raw_options = options.sort!.map do |option|
      header_int = option.type.to_i
      delta = option_number == header_int ? 0 : (header_int - option_number)
      option_number = header_int

      option.option_length = option.data.bytesize
      option.option_delta = delta
      option
    end

    if self.payload_data.size > 0
      marker = Option.new
      marker.op_delta = 15_u8
      marker.op_length = 15_u8
      self.raw_options << marker
    end
  end

  private def parse_options : Array(Option)
    option_number = 0
    raw_options.compact_map { |option|
      next if option.end_of_options?
      option_number += option.option_delta

      begin
        option.of_type Options.from_value(option_number)
      rescue error
        Log.warn(exception: error) { "unable to parse option #{option_number} with delta #{option.op_delta} data size #{option.data.size}" }
        nil
      end
    }
  end
end
