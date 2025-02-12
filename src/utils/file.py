import json
import gzip
import logging

logger = logging.getLogger("unicorcli")


def read_gzip(file_name):
    f = gzip.open(file_name, 'rb')
    return f

def read_json(file_name):

    logging.debug("Reading JSON in {}".format(file_name))
    with open(file_name, mode='rb') as file:
        json_objects = []
        for line in file:
            #logging.debug("LINE {}".format(line))
            # Try to load each line as a JSON object
            line = line.decode('utf-8').replace("'", '"')
            try:
                json_obj = json.loads(line)
                json_objects.append(json_obj)
                #logging.debug("Read JSON from file: {}".format(json_obj))
            except json.JSONDecodeError as e:
                logging.warning(f"JSON decoding error in {format(file_name)}: {e}")
                # Handle invalid JSON syntax if needed
                pass
    #logging.debug("Read JSON from file: {}".format(json_objects))
    return json_objects

def read_generic(file_name):
    f = open(file_name, mode='rt')
    return f

def read_file(file_path, delete_after_read):
    logging.debug("Parsing {}".format(file_path.absolute()))

    is_minified = False
    file_iter = None
    if file_path.suffix == ".json":
        file_iter = read_json(file_path.absolute())
    elif file_path.suffix == ".gz":
        file_iter = read_gzip(file_path.absolute())
    elif file_path.suffix == ".gz_minified":
        file_iter = read_gzip(file_path.absolute())
        is_minified = True
    elif file_path.suffix == ".txt":
        file_iter = read_generic(file_path.absolute())
    elif file_path.suffix == ".last":
        file_iter = read_generic(file_path.absolute())
    else:
        logging.warning("File {} is not in valid format".format(file_path))
    if delete_after_read:
      # We have the data from the file, let's delete the file now
        logging.debug("Deleting {}".format(file_path))
        with open(file_path, 'w') as file:
            file.write("")  # Write an empty string to the file and automatically close it
    else:
        logging.debug("NOT deleting {}".format(file_path))

    return file_iter, is_minified

def write_generic(file_name):
    f = open(file_name, mode='w+')
    return f
