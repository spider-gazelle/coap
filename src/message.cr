require "http"
require "bindata"
require "./option"

# coap://  default port 5683
# coaps:// default port 5684

module CoAP
  # https://tools.ietf.org/html/rfc7252#section-3
  class Message < BinData
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

      # https://tools.ietf.org/html/rfc7252#section-12.1
      enum_bits 3, code_class : CodeClass = CodeClass::Method

      # When code_class above == Method then this indicates if it's a GET POST etc
      bits 5, :code_detail
    end

    uint16 :message_id
    bytes :token, length: ->{ token_length }

    variable_array raw_options : Option, read_next: ->{
      if opt = raw_options[-1]?
        !opt.end_of_options?
      else
        # Are we EOF?
        io.pos != io.size
      end
    }

    remaining_bytes :payload_data

    def status_code
      (code_class.to_i * 100) + code_detail.to_i
    end

    def status_code=(value : Int | HTTP::Status)
      code = value.to_i
      self.code_class = CodeClass.from_value(code // 100)
      self.code_detail = (code % 100).to_u8
      value
    end

    # These do actually differ slightly from the HTTP originals
    # https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#response-codes
    def status
      HTTP::Status.from_value(status_code)
    end

    def status=(value : Int | HTTP::Status)
      self.status_code = value
    end

    def success?
      code_class.success?
    end

    def method
      raise "expected Method, not #{code_class.to_s}" unless code_class.method?
      MethodCode.from_value(code_detail)
    end

    # https://tools.ietf.org/html/rfc7252#section-12.2
    getter options : Array(Tuple(Options, Bytes)) do
      option_number = 0
      raw_options.compact_map { |option|
        next if option.end_of_options?
        option_number += option.op_delta.to_i

        begin
          opt = Options.from_value(option_number)
          {opt, option.data}
        rescue error
          Log.warn(exception: error) { "unable to parse option #{option_number} with delta #{option.op_delta} data size #{option.data.size}" }
          nil
        end
      }
    end

    # allow for reasonablly flexible header parsing
    def options=(values)
      values.map { |(header, data)|
        head = case header
               when String
                 Options.parse(header.gsub('-', '_'))
               when Options
                 header
               else
                 raise "unknown header #{header}"
               end
        {header, data.to_slice}
      }.sort { |a, b| a[0] <=> b[0] }.each do |(header, data)|

      end
      values
    end
  end
end
