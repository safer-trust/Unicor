# load secrets from places

# Load a secret from config or a file.
# A config stub must contain exactly one of
# - secret_base_key: "secret"
# - {secret_base_key}_file: "/path/to/file/with/secret"
# Return the value of the secret from above.
# It is an error to have neither set, unless allow_neither is set to False
# in which case None is returned if neither are set.
def load_from_file_or_config(config_stub, secret_base_key, logger, allow_neither=False):
    secret_val = None
    secret_file_key = secret_base_key + '_file'

    # Both stub and file must not be set; which takes precedence?
    if ( config_stub.get(secret_base_key) and config_stub.get(secret_file_key) ):
        logger.error("Both %s and %s config options set. Please choose one." % ( secret_base_key, secret_file_key ))
        exit(1)

    # Maybe at least one must be set.
    if ( config_stub.get(secret_base_key) is None and config_stub.get(secret_file_key) is None ):
        if allow_neither:
            return None
        else:
            logger.error("Neither %s nor %s are set, Please choose one." % ( secret_base_key, secret_file_key ))
            exit(1)

    # Load from file (value is on the first line)
    if config_stub.get(secret_file_key):
        try:
            secret_file = config_stub.get(secret_file_key)
            with open(secret_file, 'r') as f:
                    secret_val = f.readline()
                    secret_val = secret_val.strip()
            if ( secret_val is None or secret_val == '' ):
                logger.error("The %s %s is empty or could not be read" % ( secret_file_key, secret_file ))
                exit(1)
            return secret_val
        except FileNotFoundError as e:
                logger.error("Failure opening %s %s: %s" % ( secret_file_key, secret_file, e))
                exit(1)

    # Load from config stub
    if config_stub.get(secret_base_key):
        secret_val = config_stub.get(secret_base_key)
        secret_val = secret_val.strip()

        if ( secret_val is None or secret_val == '' ):
            logger.error("The %s config option is empty" % ( secret_base_key ))
            exit(1)
        return secret_val

    # I'm not sure anyone will get here, but just in case.
    return None
