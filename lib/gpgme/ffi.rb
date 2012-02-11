require 'ffi' unless defined?(FFI)
require 'gpgme/ffi/enums'
require 'gpgme/ffi/structs'
require 'gpgme/ffi/wrapper_functions'

module GPGME
  extend FFI::Library
  extend WrapperFunctions

  ffi_lib "gpgme"

  attach_function :gpgme_check_version,         :gpgme_check_version,         [:pointer], :string
  attach_function :gpgme_engine_check_version,  :gpgme_engine_check_version,  [:gpgme_protocol_t], :long
  attach_function :gpgme_get_engine_info__,     :gpgme_get_engine_info,       [GpgmeEngineInfo], :uint
end
