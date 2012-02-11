module GPGME
  module WrapperFunctions

    # @return [Array<EngineInfo>, Symbol] An error Symbol will be returned if an error occured. Engine Info(s) otherwise.
    def gpgme_get_engine_info
      retr  = []

      info  = GpgmeEngineInfo.new
      error = gpgme_get_engine_info__(info)

      return Err_Code_T[error] unless Err_Code_T[error] == :GPG_ERR_NO_ERROR

      while info
        retr << engine_info_from_info(info)

        return retr if info[:next].null?

        info = GpgmeEngineInfo.new info[:next]
      end
    end

    protected

    # @param [GpgmeEngineInfo] info
    # @return [EngineInfo]
    def engine_info_from_info(info)
      EngineInfo.new.tap do |e_info|
        e_info.protocol     = Protocol_T[info[:protocol]]
        e_info.file_name    = info[:file_name]
        e_info.version      = info[:version]
        e_info.req_version  = info[:req_version]
        e_info.home_dir     = info[:home_dir]
      end
    end

  end
end
