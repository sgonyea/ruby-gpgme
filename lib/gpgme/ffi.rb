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
  attach_function :gpgme_set_engine_info,       :gpgme_set_engine_info,       [:gpgme_protocol_t, :string, :string], :uint
  attach_function :gpgme_pubkey_algo_name,      :gpgme_pubkey_algo_name,      [:gpgme_pubkey_algo_t], :string
  attach_function :gpgme_hash_algo_name,        :gpgme_hash_algo_name,        [:gpgme_hash_algo_t], :string

  GPG_ERR_CODE_MASK = GPG_ERR_CODE_DIM - 1
  def self.gpgme_err_code(err_code)
    err_code & GPG_ERR_CODE_MASK
  end

end
