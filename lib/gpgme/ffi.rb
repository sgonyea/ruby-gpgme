require 'ffi' unless defined?(FFI)
require 'gpgme/ffi/enums'

module GPGME
  extend FFI::Library

  ffi_lib "gpgme"


  attach_function :gpgme_check_version,         :gpgme_check_version, [:pointer], :string
  attach_function :gpgme_engine_check_version,  :gpgme_engine_check_version, [:gpgme_protocol_t], :long
end
