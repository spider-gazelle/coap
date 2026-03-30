require "bindata"
require "../coap"

module CoAP
  class Option < BinData
    endian big

    # Options
    bit_field do
      bits 4, :op_delta
      bits 4, :op_length
    end

    field delta_8bit : UInt8, onlyif: -> { op_delta == 13_u8 }
    field delta_16bit : UInt16, onlyif: -> { op_delta == 14_u8 }

    def option_delta : Int32
      case op_delta
      when 13_u8
        delta_8bit.to_i + 13
      when 14_u8
        delta_16bit.to_i + 269
      when 15_u8
        -1
      else
        op_delta.to_i
      end
    end

    def option_delta=(size : Int)
      value = size.to_i

      if value < 13
        self.op_delta = value.to_u8
      elsif value > 269
        self.op_delta = 14_u8
        self.delta_16bit = (value - 269).to_u16
      else
        self.op_delta = 13_u8
        self.delta_8bit = (value - 13).to_u8
      end

      size
    end

    field length_8bit : UInt8, onlyif: -> { op_length == 13_u8 }
    field length_16bit : UInt16, onlyif: -> { op_length == 14_u8 }

    def option_length : Int32
      case op_length
      when 13_u8
        length_8bit.to_i + 13
      when 14_u8
        length_16bit.to_i + 269
      when 15_u8
        -1
      else
        op_length.to_i
      end
    end

    def option_length=(size : Int)
      value = size.to_i

      if value < 13
        self.op_length = value.to_u8
      elsif value > 269
        self.op_length = 14_u8
        self.length_16bit = (value - 269).to_u16
      else
        self.op_length = 13_u8
        self.length_8bit = (value - 13).to_u8
      end

      size
    end

    field data : Bytes, length: -> { op_length == 15_u8 ? 0 : option_length }

    def end_of_options?
      op_delta == 0xF_u8 && op_length == 0xF_u8
    end

    # Set as the option is parsed
    property type : Options = Options::If_Match

    def of_type(@type : Options) : self
      self
    end

    # Make options sortable
    def <=>(other)
      self.type <=> other.type
    end

    # ameba:disable Naming/AccessorMethodName
    def set_data(value : Bytes) : self
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
      of_type(Options::Observe)
    end

    # https://datatracker.ietf.org/doc/html/rfc7959#section-2.2
    struct Block
      property number : UInt32
      property? more : Bool
      property szx : UInt32

      def size
        2**(@szx + 4)
      end

      def initialize(@number, @more = false, @szx = 0b110_u32)
      end

      def to_option(type : CoAP::Options = CoAP::Options::Block1)
        Option.new.block(self).of_type(type)
      end
    end

    # https://datatracker.ietf.org/doc/html/rfc7959#section-2.2
    def block
      # blocks are max 3 bytes
      raw = parse_integer(max_size: 3)
      number = raw >> 4
      more = (raw & 0b1000) > 0
      szx = raw & 0b111

      Block.new(number, more, szx)
    end

    def block(block : Block)
      number = block.number << 4
      number = number | (block.more? ? 0b1000 : 0)
      number = number | (block.szx & 0b111)
      write_integer(number, max_size: 3)
      self
    end

    # https://tools.ietf.org/html/rfc7252#section-12.3
    def content_type(string : String)
      number = CONTENT_FORMAT[string.split(';', 2)[0]]
      write_integer(number, max_size: 2)
      of_type(Options::Content_Format)
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
      of_type(Options::Max_Age)
    end

    # https://tools.ietf.org/html/rfc7252#section-5.10
    def uri_port
      parse_integer(max_size: 2)
    end

    def uri_port(number : Int)
      write_integer(number, max_size: 2)
      of_type(Options::Uri_Port)
    end

    def string
      String.new(data)
    end

    def string(data : String)
      self.data = data.to_slice
      self.option_length = self.data.size
      self
    end

    def self.from_uri(uri : URI) : Array(Option)
      options = [] of Option
      options << Option.new.string(uri.host.as(String)).of_type(Options::Uri_Host) if uri.host.presence
      default_port = uri.scheme.presence ? URI.default_port(uri.scheme.as(String).downcase) : 5683
      options << Option.new.uri_port(uri.port.as(Int32)) if uri.port && uri.port != default_port
      options.concat uri.path.split('/').compact_map { |segment| Option.new.string(segment).of_type(Options::Uri_Path) if segment.presence }
      uri.query_params.each do |param, value|
        param = "#{param}=#{value}" if value.presence
        options << Option.new.string(param).of_type(Options::Uri_Query)
      end
      options
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
        while start < 3 && bytes[start] == 0_u8
          start += 1
        end

        self.data = bytes[start..-1]
        self.option_length = self.data.size
      end
      number
    end
  end
end
