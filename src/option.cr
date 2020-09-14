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
      uint8 {{name}}_16bit, onlyif: ->{ op_{{name.id}} == 14_u8 }

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
          op_{{name.id}} = length.to_u8
        elsif length > 269
          op_{{name.id}} = 14_u8
          {{name.id}}_16bit = (length - 269).to_u16
        else
          op_{{name.id}} = 13_u8
          {{name.id}}_8bit = (length - 13).to_u8
        end

        size
      end
    {% end %}

    bytes :data, length: ->{ op_length == 15_u8 ? 0 : option_length }

    def end_of_options?
      op_delta == 0xF_u8 && op_length == 0xF_u8
    end
  end
end
