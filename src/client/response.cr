require "../coap"
require "http"

class CoAP::Response < HTTP::Client::Response
  property! message : CoAP::Message
  delegate type, message_id, token, version, to: message

  def self.from_coap(message : CoAP::Message)
    raise "expected a response not a request message" if message.code_class == CoAP::CodeClass::Method
    status_code = message.status_code.to_i

    headers = HTTP::Headers.new
    message.options.each do |option|
      header_key = option.type.to_s.gsub('_', '-')

      case option.type
      when .observe?, .max_age?, .size1?, .uri_port?
        headers.add(header_key, option.max_age.to_s)
      when .content_format?, .accept?
        headers.add(header_key, option.content_type)
      when .uri_host?, .uri_path?, .uri_query?, .location_path?, .location_query?, .proxy_uri?, .proxy_scheme?
        headers.add(header_key, option.string)
      when .e_tag?
        headers.add(header_key, option.data.hexstring)
      else
        Log.warn { "unexpected CoAP header: #{option.type}" }
      end
    end

    body = String.new(message.payload_data).presence

    resp = CoAP::Response.new(status_code, body, headers)
    resp.message = message
    resp
  end
end
