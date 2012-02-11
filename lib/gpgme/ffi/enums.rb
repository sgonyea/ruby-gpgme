require 'gpgme/ffi/enum_constants'

module GPGME
  extend FFI::Library

  Status_Code_T = enum :gpgme_status_code_t, [
    :GPGME_STATUS_EOF,                  GPGME_STATUS_EOF,

    :GPGME_STATUS_ENTER,                GPGME_STATUS_ENTER,
    :GPGME_STATUS_LEAVE,                GPGME_STATUS_LEAVE,
    :GPGME_STATUS_ABORT,                GPGME_STATUS_ABORT,

    :GPGME_STATUS_GOODSIG,              GPGME_STATUS_GOODSIG,
    :GPGME_STATUS_BADSIG,               GPGME_STATUS_BADSIG,
    :GPGME_STATUS_ERRSIG,               GPGME_STATUS_ERRSIG,

    :GPGME_STATUS_BADARMOR,             GPGME_STATUS_BADARMOR,

    :GPGME_STATUS_RSA_OR_IDEA,          GPGME_STATUS_RSA_OR_IDEA,
    :GPGME_STATUS_KEYEXPIRED,           GPGME_STATUS_KEYEXPIRED,
    :GPGME_STATUS_KEYREVOKED,           GPGME_STATUS_KEYREVOKED,

    :GPGME_STATUS_TRUST_UNDEFINED,      GPGME_STATUS_TRUST_UNDEFINED,
    :GPGME_STATUS_TRUST_NEVER,          GPGME_STATUS_TRUST_NEVER,
    :GPGME_STATUS_TRUST_MARGINAL,       GPGME_STATUS_TRUST_MARGINAL,
    :GPGME_STATUS_TRUST_FULLY,          GPGME_STATUS_TRUST_FULLY,
    :GPGME_STATUS_TRUST_ULTIMATE,       GPGME_STATUS_TRUST_ULTIMATE,

    :GPGME_STATUS_SHM_INFO,             GPGME_STATUS_SHM_INFO,
    :GPGME_STATUS_SHM_GET,              GPGME_STATUS_SHM_GET,
    :GPGME_STATUS_SHM_GET_BOOL,         GPGME_STATUS_SHM_GET_BOOL,
    :GPGME_STATUS_SHM_GET_HIDDEN,       GPGME_STATUS_SHM_GET_HIDDEN,

    :GPGME_STATUS_NEED_PASSPHRASE,      GPGME_STATUS_NEED_PASSPHRASE,
    :GPGME_STATUS_VALIDSIG,             GPGME_STATUS_VALIDSIG,
    :GPGME_STATUS_SIG_ID,               GPGME_STATUS_SIG_ID,
    :GPGME_STATUS_ENC_TO,               GPGME_STATUS_ENC_TO,
    :GPGME_STATUS_NODATA,               GPGME_STATUS_NODATA,
    :GPGME_STATUS_BAD_PASSPHRASE,       GPGME_STATUS_BAD_PASSPHRASE,
    :GPGME_STATUS_NO_PUBKEY,            GPGME_STATUS_NO_PUBKEY,
    :GPGME_STATUS_NO_SECKEY,            GPGME_STATUS_NO_SECKEY,
    :GPGME_STATUS_NEED_PASSPHRASE_SYM,  GPGME_STATUS_NEED_PASSPHRASE_SYM,
    :GPGME_STATUS_DECRYPTION_FAILED,    GPGME_STATUS_DECRYPTION_FAILED,
    :GPGME_STATUS_DECRYPTION_OKAY,      GPGME_STATUS_DECRYPTION_OKAY,
    :GPGME_STATUS_MISSING_PASSPHRASE,   GPGME_STATUS_MISSING_PASSPHRASE,
    :GPGME_STATUS_GOOD_PASSPHRASE,      GPGME_STATUS_GOOD_PASSPHRASE,
    :GPGME_STATUS_GOODMDC,              GPGME_STATUS_GOODMDC,
    :GPGME_STATUS_BADMDC,               GPGME_STATUS_BADMDC,
    :GPGME_STATUS_ERRMDC,               GPGME_STATUS_ERRMDC,
    :GPGME_STATUS_IMPORTED,             GPGME_STATUS_IMPORTED,
    :GPGME_STATUS_IMPORT_OK,            GPGME_STATUS_IMPORT_OK,
    :GPGME_STATUS_IMPORT_PROBLEM,       GPGME_STATUS_IMPORT_PROBLEM,
    :GPGME_STATUS_IMPORT_RES,           GPGME_STATUS_IMPORT_RES,
    :GPGME_STATUS_FILE_START,           GPGME_STATUS_FILE_START,
    :GPGME_STATUS_FILE_DONE,            GPGME_STATUS_FILE_DONE,
    :GPGME_STATUS_FILE_ERROR,           GPGME_STATUS_FILE_ERROR,

    :GPGME_STATUS_BEGIN_DECRYPTION,     GPGME_STATUS_BEGIN_DECRYPTION,
    :GPGME_STATUS_END_DECRYPTION,       GPGME_STATUS_END_DECRYPTION,
    :GPGME_STATUS_BEGIN_ENCRYPTION,     GPGME_STATUS_BEGIN_ENCRYPTION,
    :GPGME_STATUS_END_ENCRYPTION,       GPGME_STATUS_END_ENCRYPTION,

    :GPGME_STATUS_DELETE_PROBLEM,       GPGME_STATUS_DELETE_PROBLEM,
    :GPGME_STATUS_GET_BOOL,             GPGME_STATUS_GET_BOOL,
    :GPGME_STATUS_GET_LINE,             GPGME_STATUS_GET_LINE,
    :GPGME_STATUS_GET_HIDDEN,           GPGME_STATUS_GET_HIDDEN,
    :GPGME_STATUS_GOT_IT,               GPGME_STATUS_GOT_IT,
    :GPGME_STATUS_PROGRESS,             GPGME_STATUS_PROGRESS,
    :GPGME_STATUS_SIG_CREATED,          GPGME_STATUS_SIG_CREATED,
    :GPGME_STATUS_SESSION_KEY,          GPGME_STATUS_SESSION_KEY,
    :GPGME_STATUS_NOTATION_NAME,        GPGME_STATUS_NOTATION_NAME,
    :GPGME_STATUS_NOTATION_DATA,        GPGME_STATUS_NOTATION_DATA,
    :GPGME_STATUS_POLICY_URL,           GPGME_STATUS_POLICY_URL,
    :GPGME_STATUS_BEGIN_STREAM,         GPGME_STATUS_BEGIN_STREAM,
    :GPGME_STATUS_END_STREAM,           GPGME_STATUS_END_STREAM,
    :GPGME_STATUS_KEY_CREATED,          GPGME_STATUS_KEY_CREATED,
    :GPGME_STATUS_USERID_HINT,          GPGME_STATUS_USERID_HINT,
    :GPGME_STATUS_UNEXPECTED,           GPGME_STATUS_UNEXPECTED,
    :GPGME_STATUS_INV_RECP,             GPGME_STATUS_INV_RECP,
    :GPGME_STATUS_NO_RECP,              GPGME_STATUS_NO_RECP,
    :GPGME_STATUS_ALREADY_SIGNED,       GPGME_STATUS_ALREADY_SIGNED,
    :GPGME_STATUS_SIGEXPIRED,           GPGME_STATUS_SIGEXPIRED,
    :GPGME_STATUS_EXPSIG,               GPGME_STATUS_EXPSIG,
    :GPGME_STATUS_EXPKEYSIG,            GPGME_STATUS_EXPKEYSIG,
    :GPGME_STATUS_TRUNCATED,            GPGME_STATUS_TRUNCATED,
    :GPGME_STATUS_ERROR,                GPGME_STATUS_ERROR,
    :GPGME_STATUS_NEWSIG,               GPGME_STATUS_NEWSIG,
    :GPGME_STATUS_REVKEYSIG,            GPGME_STATUS_REVKEYSIG,
    :GPGME_STATUS_SIG_SUBPACKET,        GPGME_STATUS_SIG_SUBPACKET,
    :GPGME_STATUS_NEED_PASSPHRASE_PIN,  GPGME_STATUS_NEED_PASSPHRASE_PIN,
    :GPGME_STATUS_SC_OP_FAILURE,        GPGME_STATUS_SC_OP_FAILURE,
    :GPGME_STATUS_SC_OP_SUCCESS,        GPGME_STATUS_SC_OP_SUCCESS,
    :GPGME_STATUS_CARDCTRL,             GPGME_STATUS_CARDCTRL,
    :GPGME_STATUS_BACKUP_KEY_CREATED,   GPGME_STATUS_BACKUP_KEY_CREATED,
    :GPGME_STATUS_PKA_TRUST_BAD,        GPGME_STATUS_PKA_TRUST_BAD,
    :GPGME_STATUS_PKA_TRUST_GOOD,       GPGME_STATUS_PKA_TRUST_GOOD,

    :GPGME_STATUS_PLAINTEXT,            GPGME_STATUS_PLAINTEXT,
    :GPGME_STATUS_INV_SGNR,             GPGME_STATUS_INV_SGNR,
    :GPGME_STATUS_NO_SGNR,              GPGME_STATUS_NO_SGNR,
    :GPGME_STATUS_SUCCESS,              GPGME_STATUS_SUCCESS
  ]

  Protocol_T = enum :gpgme_protocol_t, [
    :GPGME_PROTOCOL_OpenPGP,  GPGME_PROTOCOL_OpenPGP,
    :GPGME_PROTOCOL_CMS,      GPGME_PROTOCOL_CMS,
    :GPGME_PROTOCOL_GPGCONF,  GPGME_PROTOCOL_GPGCONF,
    :GPGME_PROTOCOL_ASSUAN,   GPGME_PROTOCOL_ASSUAN,
    :GPGME_PROTOCOL_G13,      GPGME_PROTOCOL_G13,
    :GPGME_PROTOCOL_UISERVER, GPGME_PROTOCOL_UISERVER,
    :GPGME_PROTOCOL_DEFAULT,  GPGME_PROTOCOL_DEFAULT,
    :GPGME_PROTOCOL_UNKNOWN,  GPGME_PROTOCOL_UNKNOWN
  ]

  Attr_T = enum :gpgme_attr_t, [
    :GPGME_ATTR_KEYID,         GPGME_ATTR_KEYID,
    :GPGME_ATTR_FPR,           GPGME_ATTR_FPR,
    :GPGME_ATTR_ALGO,          GPGME_ATTR_ALGO,
    :GPGME_ATTR_LEN,           GPGME_ATTR_LEN,
    :GPGME_ATTR_CREATED,       GPGME_ATTR_CREATED,
    :GPGME_ATTR_EXPIRE,        GPGME_ATTR_EXPIRE,
    :GPGME_ATTR_OTRUST,        GPGME_ATTR_OTRUST,
    :GPGME_ATTR_USERID,        GPGME_ATTR_USERID,
    :GPGME_ATTR_NAME,          GPGME_ATTR_NAME,
    :GPGME_ATTR_EMAIL,         GPGME_ATTR_EMAIL,
    :GPGME_ATTR_COMMENT,       GPGME_ATTR_COMMENT,
    :GPGME_ATTR_VALIDITY,      GPGME_ATTR_VALIDITY,
    :GPGME_ATTR_LEVEL,         GPGME_ATTR_LEVEL,
    :GPGME_ATTR_TYPE,          GPGME_ATTR_TYPE,
    :GPGME_ATTR_IS_SECRET,     GPGME_ATTR_IS_SECRET,
    :GPGME_ATTR_KEY_REVOKED,   GPGME_ATTR_KEY_REVOKED,
    :GPGME_ATTR_KEY_INVALID,   GPGME_ATTR_KEY_INVALID,
    :GPGME_ATTR_UID_REVOKED,   GPGME_ATTR_UID_REVOKED,
    :GPGME_ATTR_UID_INVALID,   GPGME_ATTR_UID_INVALID,
    :GPGME_ATTR_KEY_CAPS,      GPGME_ATTR_KEY_CAPS,
    :GPGME_ATTR_CAN_ENCRYPT,   GPGME_ATTR_CAN_ENCRYPT,
    :GPGME_ATTR_CAN_SIGN,      GPGME_ATTR_CAN_SIGN,
    :GPGME_ATTR_CAN_CERTIFY,   GPGME_ATTR_CAN_CERTIFY,
    :GPGME_ATTR_KEY_EXPIRED,   GPGME_ATTR_KEY_EXPIRED,
    :GPGME_ATTR_KEY_DISABLED,  GPGME_ATTR_KEY_DISABLED,
    :GPGME_ATTR_SERIAL,        GPGME_ATTR_SERIAL,
    :GPGME_ATTR_ISSUER,        GPGME_ATTR_ISSUER,
    :GPGME_ATTR_CHAINID,       GPGME_ATTR_CHAINID,
    :GPGME_ATTR_SIG_STATUS,    GPGME_ATTR_SIG_STATUS,
    :GPGME_ATTR_ERRTOK,        GPGME_ATTR_ERRTOK,
    :GPGME_ATTR_SIG_SUMMARY,   GPGME_ATTR_SIG_SUMMARY,
    :GPGME_ATTR_SIG_CLASS,     GPGME_ATTR_SIG_CLASS
  ]

  Err_Code_T = enum :gpgme_err_code_t, [
    :GPG_ERR_NO_ERROR,                GPG_ERR_NO_ERROR,
    :GPG_ERR_GENERAL,                 GPG_ERR_GENERAL,
    :GPG_ERR_UNKNOWN_PACKET,          GPG_ERR_UNKNOWN_PACKET,
    :GPG_ERR_UNKNOWN_VERSION,         GPG_ERR_UNKNOWN_VERSION,
    :GPG_ERR_PUBKEY_ALGO,             GPG_ERR_PUBKEY_ALGO,
    :GPG_ERR_DIGEST_ALGO,             GPG_ERR_DIGEST_ALGO,
    :GPG_ERR_BAD_PUBKEY,              GPG_ERR_BAD_PUBKEY,
    :GPG_ERR_BAD_SECKEY,              GPG_ERR_BAD_SECKEY,
    :GPG_ERR_BAD_SIGNATURE,           GPG_ERR_BAD_SIGNATURE,
    :GPG_ERR_NO_PUBKEY,               GPG_ERR_NO_PUBKEY,
    :GPG_ERR_CHECKSUM,                GPG_ERR_CHECKSUM,
    :GPG_ERR_BAD_PASSPHRASE,          GPG_ERR_BAD_PASSPHRASE,
    :GPG_ERR_CIPHER_ALGO,             GPG_ERR_CIPHER_ALGO,
    :GPG_ERR_KEYRING_OPEN,            GPG_ERR_KEYRING_OPEN,
    :GPG_ERR_INV_PACKET,              GPG_ERR_INV_PACKET,
    :GPG_ERR_INV_ARMOR,               GPG_ERR_INV_ARMOR,
    :GPG_ERR_NO_USER_ID,              GPG_ERR_NO_USER_ID,
    :GPG_ERR_NO_SECKEY,               GPG_ERR_NO_SECKEY,
    :GPG_ERR_WRONG_SECKEY,            GPG_ERR_WRONG_SECKEY,
    :GPG_ERR_BAD_KEY,                 GPG_ERR_BAD_KEY,
    :GPG_ERR_COMPR_ALGO,              GPG_ERR_COMPR_ALGO,
    :GPG_ERR_NO_PRIME,                GPG_ERR_NO_PRIME,
    :GPG_ERR_NO_ENCODING_METHOD,      GPG_ERR_NO_ENCODING_METHOD,
    :GPG_ERR_NO_ENCRYPTION_SCHEME,    GPG_ERR_NO_ENCRYPTION_SCHEME,
    :GPG_ERR_NO_SIGNATURE_SCHEME,     GPG_ERR_NO_SIGNATURE_SCHEME,
    :GPG_ERR_INV_ATTR,                GPG_ERR_INV_ATTR,
    :GPG_ERR_NO_VALUE,                GPG_ERR_NO_VALUE,
    :GPG_ERR_NOT_FOUND,               GPG_ERR_NOT_FOUND,
    :GPG_ERR_VALUE_NOT_FOUND,         GPG_ERR_VALUE_NOT_FOUND,
    :GPG_ERR_SYNTAX,                  GPG_ERR_SYNTAX,
    :GPG_ERR_BAD_MPI,                 GPG_ERR_BAD_MPI,
    :GPG_ERR_INV_PASSPHRASE,          GPG_ERR_INV_PASSPHRASE,
    :GPG_ERR_SIG_CLASS,               GPG_ERR_SIG_CLASS,
    :GPG_ERR_RESOURCE_LIMIT,          GPG_ERR_RESOURCE_LIMIT,
    :GPG_ERR_INV_KEYRING,             GPG_ERR_INV_KEYRING,
    :GPG_ERR_TRUSTDB,                 GPG_ERR_TRUSTDB,
    :GPG_ERR_BAD_CERT,                GPG_ERR_BAD_CERT,
    :GPG_ERR_INV_USER_ID,             GPG_ERR_INV_USER_ID,
    :GPG_ERR_UNEXPECTED,              GPG_ERR_UNEXPECTED,
    :GPG_ERR_TIME_CONFLICT,           GPG_ERR_TIME_CONFLICT,
    :GPG_ERR_KEYSERVER,               GPG_ERR_KEYSERVER,
    :GPG_ERR_WRONG_PUBKEY_ALGO,       GPG_ERR_WRONG_PUBKEY_ALGO,
    :GPG_ERR_TRIBUTE_TO_D_A,          GPG_ERR_TRIBUTE_TO_D_A,
    :GPG_ERR_WEAK_KEY,                GPG_ERR_WEAK_KEY,
    :GPG_ERR_INV_KEYLEN,              GPG_ERR_INV_KEYLEN,
    :GPG_ERR_INV_ARG,                 GPG_ERR_INV_ARG,
    :GPG_ERR_BAD_URI,                 GPG_ERR_BAD_URI,
    :GPG_ERR_INV_URI,                 GPG_ERR_INV_URI,
    :GPG_ERR_NETWORK,                 GPG_ERR_NETWORK,
    :GPG_ERR_UNKNOWN_HOST,            GPG_ERR_UNKNOWN_HOST,
    :GPG_ERR_SELFTEST_FAILED,         GPG_ERR_SELFTEST_FAILED,
    :GPG_ERR_NOT_ENCRYPTED,           GPG_ERR_NOT_ENCRYPTED,
    :GPG_ERR_NOT_PROCESSED,           GPG_ERR_NOT_PROCESSED,
    :GPG_ERR_UNUSABLE_PUBKEY,         GPG_ERR_UNUSABLE_PUBKEY,
    :GPG_ERR_UNUSABLE_SECKEY,         GPG_ERR_UNUSABLE_SECKEY,
    :GPG_ERR_INV_VALUE,               GPG_ERR_INV_VALUE,
    :GPG_ERR_BAD_CERT_CHAIN,          GPG_ERR_BAD_CERT_CHAIN,
    :GPG_ERR_MISSING_CERT,            GPG_ERR_MISSING_CERT,
    :GPG_ERR_NO_DATA,                 GPG_ERR_NO_DATA,
    :GPG_ERR_BUG,                     GPG_ERR_BUG,
    :GPG_ERR_NOT_SUPPORTED,           GPG_ERR_NOT_SUPPORTED,
    :GPG_ERR_INV_OP,                  GPG_ERR_INV_OP,
    :GPG_ERR_TIMEOUT,                 GPG_ERR_TIMEOUT,
    :GPG_ERR_INTERNAL,                GPG_ERR_INTERNAL,
    :GPG_ERR_EOF_GCRYPT,              GPG_ERR_EOF_GCRYPT,
    :GPG_ERR_INV_OBJ,                 GPG_ERR_INV_OBJ,
    :GPG_ERR_TOO_SHORT,               GPG_ERR_TOO_SHORT,
    :GPG_ERR_TOO_LARGE,               GPG_ERR_TOO_LARGE,
    :GPG_ERR_NO_OBJ,                  GPG_ERR_NO_OBJ,
    :GPG_ERR_NOT_IMPLEMENTED,         GPG_ERR_NOT_IMPLEMENTED,
    :GPG_ERR_CONFLICT,                GPG_ERR_CONFLICT,
    :GPG_ERR_INV_CIPHER_MODE,         GPG_ERR_INV_CIPHER_MODE,
    :GPG_ERR_INV_FLAG,                GPG_ERR_INV_FLAG,
    :GPG_ERR_INV_HANDLE,              GPG_ERR_INV_HANDLE,
    :GPG_ERR_TRUNCATED,               GPG_ERR_TRUNCATED,
    :GPG_ERR_INCOMPLETE_LINE,         GPG_ERR_INCOMPLETE_LINE,
    :GPG_ERR_INV_RESPONSE,            GPG_ERR_INV_RESPONSE,
    :GPG_ERR_NO_AGENT,                GPG_ERR_NO_AGENT,
    :GPG_ERR_AGENT,                   GPG_ERR_AGENT,
    :GPG_ERR_INV_DATA,                GPG_ERR_INV_DATA,
    :GPG_ERR_ASSUAN_SERVER_FAULT,     GPG_ERR_ASSUAN_SERVER_FAULT,
    :GPG_ERR_ASSUAN,                  GPG_ERR_ASSUAN,
    :GPG_ERR_INV_SESSION_KEY,         GPG_ERR_INV_SESSION_KEY,
    :GPG_ERR_INV_SEXP,                GPG_ERR_INV_SEXP,
    :GPG_ERR_UNSUPPORTED_ALGORITHM,   GPG_ERR_UNSUPPORTED_ALGORITHM,
    :GPG_ERR_NO_PIN_ENTRY,            GPG_ERR_NO_PIN_ENTRY,
    :GPG_ERR_PIN_ENTRY,               GPG_ERR_PIN_ENTRY,
    :GPG_ERR_BAD_PIN,                 GPG_ERR_BAD_PIN,
    :GPG_ERR_INV_NAME,                GPG_ERR_INV_NAME,
    :GPG_ERR_BAD_DATA,                GPG_ERR_BAD_DATA,
    :GPG_ERR_INV_PARAMETER,           GPG_ERR_INV_PARAMETER,
    :GPG_ERR_WRONG_CARD,              GPG_ERR_WRONG_CARD,
    :GPG_ERR_NO_DIRMNGR,              GPG_ERR_NO_DIRMNGR,
    :GPG_ERR_DIRMNGR,                 GPG_ERR_DIRMNGR,
    :GPG_ERR_CERT_REVOKED,            GPG_ERR_CERT_REVOKED,
    :GPG_ERR_NO_CRL_KNOWN,            GPG_ERR_NO_CRL_KNOWN,
    :GPG_ERR_CRL_TOO_OLD,             GPG_ERR_CRL_TOO_OLD,
    :GPG_ERR_LINE_TOO_LONG,           GPG_ERR_LINE_TOO_LONG,
    :GPG_ERR_NOT_TRUSTED,             GPG_ERR_NOT_TRUSTED,
    :GPG_ERR_CANCELED,                GPG_ERR_CANCELED,
    :GPG_ERR_BAD_CA_CERT,             GPG_ERR_BAD_CA_CERT,
    :GPG_ERR_CERT_EXPIRED,            GPG_ERR_CERT_EXPIRED,
    :GPG_ERR_CERT_TOO_YOUNG,          GPG_ERR_CERT_TOO_YOUNG,
    :GPG_ERR_UNSUPPORTED_CERT,        GPG_ERR_UNSUPPORTED_CERT,
    :GPG_ERR_UNKNOWN_SEXP,            GPG_ERR_UNKNOWN_SEXP,
    :GPG_ERR_UNSUPPORTED_PROTECTION,  GPG_ERR_UNSUPPORTED_PROTECTION,
    :GPG_ERR_CORRUPTED_PROTECTION,    GPG_ERR_CORRUPTED_PROTECTION,
    :GPG_ERR_AMBIGUOUS_NAME,          GPG_ERR_AMBIGUOUS_NAME,
    :GPG_ERR_CARD,                    GPG_ERR_CARD,
    :GPG_ERR_CARD_RESET,              GPG_ERR_CARD_RESET,
    :GPG_ERR_CARD_REMOVED,            GPG_ERR_CARD_REMOVED,
    :GPG_ERR_INV_CARD,                GPG_ERR_INV_CARD,
    :GPG_ERR_CARD_NOT_PRESENT,        GPG_ERR_CARD_NOT_PRESENT,
    :GPG_ERR_NO_PKCS15_APP,           GPG_ERR_NO_PKCS15_APP,
    :GPG_ERR_NOT_CONFIRMED,           GPG_ERR_NOT_CONFIRMED,
    :GPG_ERR_CONFIGURATION,           GPG_ERR_CONFIGURATION,
    :GPG_ERR_NO_POLICY_MATCH,         GPG_ERR_NO_POLICY_MATCH,
    :GPG_ERR_INV_INDEX,               GPG_ERR_INV_INDEX,
    :GPG_ERR_INV_ID,                  GPG_ERR_INV_ID,
    :GPG_ERR_NO_SCDAEMON,             GPG_ERR_NO_SCDAEMON,
    :GPG_ERR_SCDAEMON,                GPG_ERR_SCDAEMON,
    :GPG_ERR_UNSUPPORTED_PROTOCOL,    GPG_ERR_UNSUPPORTED_PROTOCOL,
    :GPG_ERR_BAD_PIN_METHOD,          GPG_ERR_BAD_PIN_METHOD,
    :GPG_ERR_CARD_NOT_INITIALIZED,    GPG_ERR_CARD_NOT_INITIALIZED,
    :GPG_ERR_UNSUPPORTED_OPERATION,   GPG_ERR_UNSUPPORTED_OPERATION,
    :GPG_ERR_WRONG_KEY_USAGE,         GPG_ERR_WRONG_KEY_USAGE,
    :GPG_ERR_NOTHING_FOUND,           GPG_ERR_NOTHING_FOUND,
    :GPG_ERR_WRONG_BLOB_TYPE,         GPG_ERR_WRONG_BLOB_TYPE,
    :GPG_ERR_MISSING_VALUE,           GPG_ERR_MISSING_VALUE,
    :GPG_ERR_HARDWARE,                GPG_ERR_HARDWARE,
    :GPG_ERR_PIN_BLOCKED,             GPG_ERR_PIN_BLOCKED,
    :GPG_ERR_USE_CONDITIONS,          GPG_ERR_USE_CONDITIONS,
    :GPG_ERR_PIN_NOT_SYNCED,          GPG_ERR_PIN_NOT_SYNCED,
    :GPG_ERR_INV_CRL,                 GPG_ERR_INV_CRL,
    :GPG_ERR_BAD_BER,                 GPG_ERR_BAD_BER,
    :GPG_ERR_INV_BER,                 GPG_ERR_INV_BER,
    :GPG_ERR_ELEMENT_NOT_FOUND,       GPG_ERR_ELEMENT_NOT_FOUND,
    :GPG_ERR_IDENTIFIER_NOT_FOUND,    GPG_ERR_IDENTIFIER_NOT_FOUND,
    :GPG_ERR_INV_TAG,                 GPG_ERR_INV_TAG,
    :GPG_ERR_INV_LENGTH,              GPG_ERR_INV_LENGTH,
    :GPG_ERR_INV_KEYINFO,             GPG_ERR_INV_KEYINFO,
    :GPG_ERR_UNEXPECTED_TAG,          GPG_ERR_UNEXPECTED_TAG,
    :GPG_ERR_NOT_DER_ENCODED,         GPG_ERR_NOT_DER_ENCODED,
    :GPG_ERR_NO_CMS_OBJ,              GPG_ERR_NO_CMS_OBJ,
    :GPG_ERR_INV_CMS_OBJ,             GPG_ERR_INV_CMS_OBJ,
    :GPG_ERR_UNKNOWN_CMS_OBJ,         GPG_ERR_UNKNOWN_CMS_OBJ,
    :GPG_ERR_UNSUPPORTED_CMS_OBJ,     GPG_ERR_UNSUPPORTED_CMS_OBJ,
    :GPG_ERR_UNSUPPORTED_ENCODING,    GPG_ERR_UNSUPPORTED_ENCODING,
    :GPG_ERR_UNSUPPORTED_CMS_VERSION, GPG_ERR_UNSUPPORTED_CMS_VERSION,
    :GPG_ERR_UNKNOWN_ALGORITHM,       GPG_ERR_UNKNOWN_ALGORITHM,
    :GPG_ERR_INV_ENGINE,              GPG_ERR_INV_ENGINE,
    :GPG_ERR_PUBKEY_NOT_TRUSTED,      GPG_ERR_PUBKEY_NOT_TRUSTED,
    :GPG_ERR_DECRYPT_FAILED,          GPG_ERR_DECRYPT_FAILED,
    :GPG_ERR_KEY_EXPIRED,             GPG_ERR_KEY_EXPIRED,
    :GPG_ERR_SIG_EXPIRED,             GPG_ERR_SIG_EXPIRED,
    :GPG_ERR_ENCODING_PROBLEM,        GPG_ERR_ENCODING_PROBLEM,
    :GPG_ERR_INV_STATE,               GPG_ERR_INV_STATE,
    :GPG_ERR_DUP_VALUE,               GPG_ERR_DUP_VALUE,
    :GPG_ERR_MISSING_ACTION,          GPG_ERR_MISSING_ACTION,
    :GPG_ERR_MODULE_NOT_FOUND,        GPG_ERR_MODULE_NOT_FOUND,
    :GPG_ERR_INV_OID_STRING,          GPG_ERR_INV_OID_STRING,
    :GPG_ERR_INV_TIME,                GPG_ERR_INV_TIME,
    :GPG_ERR_INV_CRL_OBJ,             GPG_ERR_INV_CRL_OBJ,
    :GPG_ERR_UNSUPPORTED_CRL_VERSION, GPG_ERR_UNSUPPORTED_CRL_VERSION,
    :GPG_ERR_INV_CERT_OBJ,            GPG_ERR_INV_CERT_OBJ,
    :GPG_ERR_UNKNOWN_NAME,            GPG_ERR_UNKNOWN_NAME,
    :GPG_ERR_LOCALE_PROBLEM,          GPG_ERR_LOCALE_PROBLEM,
    :GPG_ERR_NOT_LOCKED,              GPG_ERR_NOT_LOCKED,
    :GPG_ERR_PROTOCOL_VIOLATION,      GPG_ERR_PROTOCOL_VIOLATION,
    :GPG_ERR_INV_MAC,                 GPG_ERR_INV_MAC,
    :GPG_ERR_INV_REQUEST,             GPG_ERR_INV_REQUEST,
    :GPG_ERR_UNKNOWN_EXTN,            GPG_ERR_UNKNOWN_EXTN,
    :GPG_ERR_UNKNOWN_CRIT_EXTN,       GPG_ERR_UNKNOWN_CRIT_EXTN,
    :GPG_ERR_LOCKED,                  GPG_ERR_LOCKED,
    :GPG_ERR_UNKNOWN_OPTION,          GPG_ERR_UNKNOWN_OPTION,
    :GPG_ERR_UNKNOWN_COMMAND,         GPG_ERR_UNKNOWN_COMMAND,
    :GPG_ERR_NOT_OPERATIONAL,         GPG_ERR_NOT_OPERATIONAL,
    :GPG_ERR_NO_PASSPHRASE,           GPG_ERR_NO_PASSPHRASE,
    :GPG_ERR_NO_PIN,                  GPG_ERR_NO_PIN,
    :GPG_ERR_NOT_ENABLED,             GPG_ERR_NOT_ENABLED,
    :GPG_ERR_NO_ENGINE,               GPG_ERR_NO_ENGINE,
    :GPG_ERR_MISSING_KEY,             GPG_ERR_MISSING_KEY,
    :GPG_ERR_TOO_MANY,                GPG_ERR_TOO_MANY,
    :GPG_ERR_LIMIT_REACHED,           GPG_ERR_LIMIT_REACHED,
    :GPG_ERR_NOT_INITIALIZED,         GPG_ERR_NOT_INITIALIZED,
    :GPG_ERR_MISSING_ISSUER_CERT,     GPG_ERR_MISSING_ISSUER_CERT,
    :GPG_ERR_FULLY_CANCELED,          GPG_ERR_FULLY_CANCELED,
    :GPG_ERR_UNFINISHED,              GPG_ERR_UNFINISHED,
    :GPG_ERR_BUFFER_TOO_SHORT,        GPG_ERR_BUFFER_TOO_SHORT,
    :GPG_ERR_SEXP_INV_LEN_SPEC,       GPG_ERR_SEXP_INV_LEN_SPEC,
    :GPG_ERR_SEXP_STRING_TOO_LONG,    GPG_ERR_SEXP_STRING_TOO_LONG,
    :GPG_ERR_SEXP_UNMATCHED_PAREN,    GPG_ERR_SEXP_UNMATCHED_PAREN,
    :GPG_ERR_SEXP_NOT_CANONICAL,      GPG_ERR_SEXP_NOT_CANONICAL,
    :GPG_ERR_SEXP_BAD_CHARACTER,      GPG_ERR_SEXP_BAD_CHARACTER,
    :GPG_ERR_SEXP_BAD_QUOTATION,      GPG_ERR_SEXP_BAD_QUOTATION,
    :GPG_ERR_SEXP_ZERO_PREFIX,        GPG_ERR_SEXP_ZERO_PREFIX,
    :GPG_ERR_SEXP_NESTED_DH,          GPG_ERR_SEXP_NESTED_DH,
    :GPG_ERR_SEXP_UNMATCHED_DH,       GPG_ERR_SEXP_UNMATCHED_DH,
    :GPG_ERR_SEXP_UNEXPECTED_PUNC,    GPG_ERR_SEXP_UNEXPECTED_PUNC,
    :GPG_ERR_SEXP_BAD_HEX_CHAR,       GPG_ERR_SEXP_BAD_HEX_CHAR,
    :GPG_ERR_SEXP_ODD_HEX_NUMBERS,    GPG_ERR_SEXP_ODD_HEX_NUMBERS,
    :GPG_ERR_SEXP_BAD_OCT_CHAR,       GPG_ERR_SEXP_BAD_OCT_CHAR,
    :GPG_ERR_ASS_GENERAL,             GPG_ERR_ASS_GENERAL,
    :GPG_ERR_ASS_ACCEPT_FAILED,       GPG_ERR_ASS_ACCEPT_FAILED,
    :GPG_ERR_ASS_CONNECT_FAILED,      GPG_ERR_ASS_CONNECT_FAILED,
    :GPG_ERR_ASS_INV_RESPONSE,        GPG_ERR_ASS_INV_RESPONSE,
    :GPG_ERR_ASS_INV_VALUE,           GPG_ERR_ASS_INV_VALUE,
    :GPG_ERR_ASS_INCOMPLETE_LINE,     GPG_ERR_ASS_INCOMPLETE_LINE,
    :GPG_ERR_ASS_LINE_TOO_LONG,       GPG_ERR_ASS_LINE_TOO_LONG,
    :GPG_ERR_ASS_NESTED_COMMANDS,     GPG_ERR_ASS_NESTED_COMMANDS,
    :GPG_ERR_ASS_NO_DATA_CB,          GPG_ERR_ASS_NO_DATA_CB,
    :GPG_ERR_ASS_NO_INQUIRE_CB,       GPG_ERR_ASS_NO_INQUIRE_CB,
    :GPG_ERR_ASS_NOT_A_SERVER,        GPG_ERR_ASS_NOT_A_SERVER,
    :GPG_ERR_ASS_NOT_A_CLIENT,        GPG_ERR_ASS_NOT_A_CLIENT,
    :GPG_ERR_ASS_SERVER_START,        GPG_ERR_ASS_SERVER_START,
    :GPG_ERR_ASS_READ_ERROR,          GPG_ERR_ASS_READ_ERROR,
    :GPG_ERR_ASS_WRITE_ERROR,         GPG_ERR_ASS_WRITE_ERROR,
    :GPG_ERR_ASS_TOO_MUCH_DATA,       GPG_ERR_ASS_TOO_MUCH_DATA,
    :GPG_ERR_ASS_UNEXPECTED_CMD,      GPG_ERR_ASS_UNEXPECTED_CMD,
    :GPG_ERR_ASS_UNKNOWN_CMD,         GPG_ERR_ASS_UNKNOWN_CMD,
    :GPG_ERR_ASS_SYNTAX,              GPG_ERR_ASS_SYNTAX,
    :GPG_ERR_ASS_CANCELED,            GPG_ERR_ASS_CANCELED,
    :GPG_ERR_ASS_NO_INPUT,            GPG_ERR_ASS_NO_INPUT,
    :GPG_ERR_ASS_NO_OUTPUT,           GPG_ERR_ASS_NO_OUTPUT,
    :GPG_ERR_ASS_PARAMETER,           GPG_ERR_ASS_PARAMETER,
    :GPG_ERR_ASS_UNKNOWN_INQUIRE,     GPG_ERR_ASS_UNKNOWN_INQUIRE,
    :GPG_ERR_USER_1,                  GPG_ERR_USER_1,
    :GPG_ERR_USER_2,                  GPG_ERR_USER_2,
    :GPG_ERR_USER_3,                  GPG_ERR_USER_3,
    :GPG_ERR_USER_4,                  GPG_ERR_USER_4,
    :GPG_ERR_USER_5,                  GPG_ERR_USER_5,
    :GPG_ERR_USER_6,                  GPG_ERR_USER_6,
    :GPG_ERR_USER_7,                  GPG_ERR_USER_7,
    :GPG_ERR_USER_8,                  GPG_ERR_USER_8,
    :GPG_ERR_USER_9,                  GPG_ERR_USER_9,
    :GPG_ERR_USER_10,                 GPG_ERR_USER_10,
    :GPG_ERR_USER_11,                 GPG_ERR_USER_11,
    :GPG_ERR_USER_12,                 GPG_ERR_USER_12,
    :GPG_ERR_USER_13,                 GPG_ERR_USER_13,
    :GPG_ERR_USER_14,                 GPG_ERR_USER_14,
    :GPG_ERR_USER_15,                 GPG_ERR_USER_15,
    :GPG_ERR_USER_16,                 GPG_ERR_USER_16,
    :GPG_ERR_MISSING_ERRNO,           GPG_ERR_MISSING_ERRNO,
    :GPG_ERR_UNKNOWN_ERRNO,           GPG_ERR_UNKNOWN_ERRNO,
    :GPG_ERR_EOF,                     GPG_ERR_EOF
  ]

  Err_Source_T = enum :gpgme_err_source_t, [
    :GPG_ERR_SOURCE_UNKNOWN,    GPG_ERR_SOURCE_UNKNOWN,
    :GPG_ERR_SOURCE_GCRYPT,     GPG_ERR_SOURCE_GCRYPT,
    :GPG_ERR_SOURCE_GPG,        GPG_ERR_SOURCE_GPG,
    :GPG_ERR_SOURCE_GPGSM,      GPG_ERR_SOURCE_GPGSM,
    :GPG_ERR_SOURCE_GPGAGENT,   GPG_ERR_SOURCE_GPGAGENT,
    :GPG_ERR_SOURCE_PINENTRY,   GPG_ERR_SOURCE_PINENTRY,
    :GPG_ERR_SOURCE_SCD,        GPG_ERR_SOURCE_SCD,
    :GPG_ERR_SOURCE_GPGME,      GPG_ERR_SOURCE_GPGME,
    :GPG_ERR_SOURCE_KEYBOX,     GPG_ERR_SOURCE_KEYBOX,
    :GPG_ERR_SOURCE_KSBA,       GPG_ERR_SOURCE_KSBA,
    :GPG_ERR_SOURCE_DIRMNGR,    GPG_ERR_SOURCE_DIRMNGR,
    :GPG_ERR_SOURCE_GSTI,       GPG_ERR_SOURCE_GSTI,
    :GPG_ERR_SOURCE_GPA,        GPG_ERR_SOURCE_GPA,
    :GPG_ERR_SOURCE_KLEO,       GPG_ERR_SOURCE_KLEO,
    :GPG_ERR_SOURCE_G13,        GPG_ERR_SOURCE_G13,
    :GPG_ERR_SOURCE_ANY,        GPG_ERR_SOURCE_ANY,
    :GPG_ERR_SOURCE_USER_1,     GPG_ERR_SOURCE_USER_1,
    :GPG_ERR_SOURCE_USER_2,     GPG_ERR_SOURCE_USER_2,
    :GPG_ERR_SOURCE_USER_3,     GPG_ERR_SOURCE_USER_3,
    :GPG_ERR_SOURCE_USER_4,     GPG_ERR_SOURCE_USER_4
  ]

  Pubkey_Algo_T = enum :gpgme_pubkey_algo_t, [
    :GPGME_PK_RSA,    GPGME_PK_RSA,
    :GPGME_PK_RSA_E,  GPGME_PK_RSA_E,
    :GPGME_PK_RSA_S,  GPGME_PK_RSA_S,
    :GPGME_PK_ELG_E,  GPGME_PK_ELG_E,
    :GPGME_PK_DSA,    GPGME_PK_DSA,
    :GPGME_PK_ELG,    GPGME_PK_ELG,
    :GPGME_PK_ECDSA,  GPGME_PK_ECDSA,
    :GPGME_PK_ECDH,   GPGME_PK_ECDH
  ]

  Hash_Algo_T = enum :gpgme_hash_algo_t, [
    :GPGME_MD_NONE,           GPGME_MD_NONE,
    :GPGME_MD_MD5,            GPGME_MD_MD5,
    :GPGME_MD_SHA1,           GPGME_MD_SHA1,
    :GPGME_MD_RMD160,         GPGME_MD_RMD160,
    :GPGME_MD_MD2,            GPGME_MD_MD2,
    :GPGME_MD_TIGER,          GPGME_MD_TIGER,
    :GPGME_MD_HAVAL,          GPGME_MD_HAVAL,
    :GPGME_MD_SHA256,         GPGME_MD_SHA256,
    :GPGME_MD_SHA384,         GPGME_MD_SHA384,
    :GPGME_MD_SHA512,         GPGME_MD_SHA512,
    :GPGME_MD_MD4,            GPGME_MD_MD4,
    :GPGME_MD_CRC32,          GPGME_MD_CRC32,
    :GPGME_MD_CRC32_RFC1510,  GPGME_MD_CRC32_RFC1510,
    :GPGME_MD_CRC24_RFC2440,  GPGME_MD_CRC24_RFC2440
  ]

  Data_Encoding_T = enum :gpgme_data_encoding_t, [
    :GPGME_DATA_ENCODING_NONE,    GPGME_DATA_ENCODING_NONE,
    :GPGME_DATA_ENCODING_BINARY,  GPGME_DATA_ENCODING_BINARY,
    :GPGME_DATA_ENCODING_BASE64,  GPGME_DATA_ENCODING_BASE64,
    :GPGME_DATA_ENCODING_ARMOR,   GPGME_DATA_ENCODING_ARMOR,
    :GPGME_DATA_ENCODING_URL,     GPGME_DATA_ENCODING_URL,
    :GPGME_DATA_ENCODING_URLESC,  GPGME_DATA_ENCODING_URLESC,
    :GPGME_DATA_ENCODING_URL0,    GPGME_DATA_ENCODING_URL0
  ]

  Sig_Stat_T = enum :gpgme_sig_stat_t, [
    :GPGME_SIG_STAT_NONE,         GPGME_SIG_STAT_NONE,
    :GPGME_SIG_STAT_GOOD,         GPGME_SIG_STAT_GOOD,
    :GPGME_SIG_STAT_BAD,          GPGME_SIG_STAT_BAD,
    :GPGME_SIG_STAT_NOKEY,        GPGME_SIG_STAT_NOKEY,
    :GPGME_SIG_STAT_NOSIG,        GPGME_SIG_STAT_NOSIG,
    :GPGME_SIG_STAT_ERROR,        GPGME_SIG_STAT_ERROR,
    :GPGME_SIG_STAT_DIFF,         GPGME_SIG_STAT_DIFF,
    :GPGME_SIG_STAT_GOOD_EXP,     GPGME_SIG_STAT_GOOD_EXP,
    :GPGME_SIG_STAT_GOOD_EXPKEY,  GPGME_SIG_STAT_GOOD_EXPKEY
  ]

  Sig_Sum_T = enum :gpgme_sigsum_t, [
    :GPGME_SIGSUM_VALID,        GPGME_SIGSUM_VALID,
    :GPGME_SIGSUM_GREEN,        GPGME_SIGSUM_GREEN,
    :GPGME_SIGSUM_RED,          GPGME_SIGSUM_RED,
    :GPGME_SIGSUM_KEY_REVOKED,  GPGME_SIGSUM_KEY_REVOKED,
    :GPGME_SIGSUM_KEY_EXPIRED,  GPGME_SIGSUM_KEY_EXPIRED,
    :GPGME_SIGSUM_SIG_EXPIRED,  GPGME_SIGSUM_SIG_EXPIRED,
    :GPGME_SIGSUM_KEY_MISSING,  GPGME_SIGSUM_KEY_MISSING,
    :GPGME_SIGSUM_CRL_MISSING,  GPGME_SIGSUM_CRL_MISSING,
    :GPGME_SIGSUM_CRL_TOO_OLD,  GPGME_SIGSUM_CRL_TOO_OLD,
    :GPGME_SIGSUM_BAD_POLICY,   GPGME_SIGSUM_BAD_POLICY,
    :GPGME_SIGSUM_SYS_ERROR,    GPGME_SIGSUM_SYS_ERROR
  ]

  Sig_Mode_T = enum :gpgme_sig_mode_t, [
    :GPGME_SIG_MODE_NORMAL, GPGME_SIG_MODE_NORMAL,
    :GPGME_SIG_MODE_DETACH, GPGME_SIG_MODE_DETACH,
    :GPGME_SIG_MODE_CLEAR,  GPGME_SIG_MODE_CLEAR
  ]

  Validity_T = enum :gpgme_validity_t, [
    :GPGME_VALIDITY_UNKNOWN,    GPGME_VALIDITY_UNKNOWN,
    :GPGME_VALIDITY_UNDEFINED,  GPGME_VALIDITY_UNDEFINED,
    :GPGME_VALIDITY_NEVER,      GPGME_VALIDITY_NEVER,
    :GPGME_VALIDITY_MARGINAL,   GPGME_VALIDITY_MARGINAL,
    :GPGME_VALIDITY_FULL,       GPGME_VALIDITY_FULL,
    :GPGME_VALIDITY_ULTIMATE,   GPGME_VALIDITY_ULTIMATE
  ]
end
