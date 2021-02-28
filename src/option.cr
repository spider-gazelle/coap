require "bindata"

module CoAP
  class Option < BinData
    endian big

    # Options
    bit_field do
      bits 4, :op_delta
      bits 4, :op_length
    end

    {% for name in [:delta, :length] %}
      uint8 {{name}}_8bit, onlyif: ->{ op_{{name.id}} == 13_u8 }
      uint16 {{name}}_16bit, onlyif: ->{ op_{{name.id}} == 14_u8 }

      def option_{{name.id}} : Int32
        case op_{{name.id}}
        when 13_u8
          {{name.id}}_8bit.to_i + 13
        when 14_u8
          {{name.id}}_16bit.to_i + 269
        when 15_u8
          # This is just a marker for the end
          -1
        else
          op_{{name.id}}.to_i
        end
      end

      def option_{{name.id}}=(size : Int)
        length = size.to_i

        if length < 13
          self.op_{{name.id}} = length.to_u8
        elsif length > 269
          self.op_{{name.id}} = 14_u8
          self.{{name.id}}_16bit = (length - 269).to_u16
        else
          self.op_{{name.id}} = 13_u8
          self.{{name.id}}_8bit = (length - 13).to_u8
        end

        size
      end
    {% end %}

    bytes :data, length: ->{ op_length == 15_u8 ? 0 : option_length }

    def end_of_options?
      op_delta == 0xF_u8 && op_length == 0xF_u8
    end

    # Set as the option is parsed
    getter! type : Options

    def type(@type : Options)
      self
    end

    # Make options sortable
    def <=>(option)
      self.type <=> option.type
    end

    def data(value)
      @data = value
      self
    end

    # https://tools.ietf.org/html/draft-ietf-core-observe-08
    def observation
      # Observations are max 3 bytes
      # https://tools.ietf.org/html/draft-ietf-core-observe-08#section-2
      parse_integer(max_size: 3)
    end

    def observation(number : Int)
      write_integer(number, max_size: 3)
      self
    end

    # https://tools.ietf.org/html/rfc7252#section-12.3
    def content_type(string : String)
      number = CONTENT_FORMAT[string.split(';', 2)[0]]
      write_integer(number, max_size: 2)
      self
    end

    def content_type
      LOOKUP_FORMAT[parse_integer(max_size: 2).to_u16]
    end

    # https://tools.ietf.org/html/rfc7252#section-5.10
    def max_age
      parse_integer(max_size: 4)
    end

    def max_age(number : Int)
      write_integer(number, max_size: 4)
      self
    end

    # https://tools.ietf.org/html/rfc7252#section-5.10
    def uri_port
      parse_integer(max_size: 2)
    end

    def uri_port(number : Int)
      write_integer(number, max_size: 2)
      self
    end

    def string
      String.new(data)
    end

    def string(data : String)
      self.data = data.to_slice
      self.option_length = self.data.size
      self
    end

    # We need to pad the potentially small integers
    protected def parse_integer(max_size)
      return 0_u32 if data.size == 0
      raise "invalid integer, size #{data.size} maximum is #{max_size}" if data.size > max_size

      # we want to normalise an observation
      buffer = IO::Memory.new(Bytes.new(4))
      buffer.pos = 4 - data.size
      buffer.write data
      buffer.rewind
      buffer.read_bytes(UInt32, IO::ByteFormat::BigEndian)
    end

    # Minimal data written
    protected def write_integer(number, max_size)
      if number == 0
        self.data = Bytes.new(0)
        self.option_length = 0
      else
        buffer = IO::Memory.new(4)
        buffer.write_bytes(number.to_u32, IO::ByteFormat::BigEndian)
        bytes = buffer.to_slice

        start = 4 - max_size
        bytes.each_with_index do |byte, index|
          next if index < start
          start = index
          break if byte > 0_u8
        end

        self.data = bytes[start..-1]
        self.option_length = self.data.size
      end
      number
    end
  end
end
