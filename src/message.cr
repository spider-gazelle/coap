require "http"
require "bindata"
require "./option"

module CoAP
  # https://tools.ietf.org/html/rfc7252#section-3
  class Message < BinData
    endian big

    enum Type
      Confirmable     = 0
      NonConfirmable
      Acknowledgement
      Reset
    end

    bit_field do
      # Should always be 1
      bits 2, :version, value: ->{ 1_u8 }
      # https://tools.ietf.org/html/rfc7252#section-4.3
      enum_bits 2, type : Type = Type::Confirmable

      bits 4, :token_length, value: ->{ token.size }

      # https://tools.ietf.org/html/rfc7252#section-12.1
      enum_bits 3, code_class : CodeClass = CodeClass::Method
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

    # Starts with 0xFF which can be ignored
    remaining_bytes :payload_data

    def status_code
      (code_class.to_i * 100) + code_detail.to_i
    end

    # These do actually differ slightly from the HTTP originals
    # https://www.iana.org/assignments/core-parameters/core-parameters.xhtml#response-codes
    def status
      HTTP::Status.from_value(status_code)
    end

    def success?
      code_class.success?
    end

    def method
      raise "expected Method, not #{code_class.to_s}" unless code_class.method?
      MethodCode.from_value(code_detail)
    end

    @options : Hash(Int32, IO::Memory)? = nil

    # https://tools.ietf.org/html/rfc7252#section-12.2
    def options : Hash(Int32, IO::Memory)
      if opts = @options
        return opts
      end

      opts = Hash(Int32, IO::Memory).new { |h, k| h[k] = IO::Memory.new(16) }
      option_number = 0
      raw_options.each do |option|
        next if option.end_of_options?
        option_number += option.op_delta.to_i
        opts[option_number].write option.data
      end
      @options = opts
      opts
    end
  end
end
