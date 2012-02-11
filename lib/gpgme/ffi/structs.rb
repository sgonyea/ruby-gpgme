module GPGME

  # _gpgme_engine_info / gpgme_engine_info_t
  class GpgmeEngineInfo < FFI::Struct
    layout  :next,        :pointer, # LL - A pointer to a GpgmeEngineInfo
            :protocol,    :gpgme_protocol_t,
            :file_name,   :string,
            :version,     :string,
            :req_version, :string,
            :home_dir,    :string
  end

end
