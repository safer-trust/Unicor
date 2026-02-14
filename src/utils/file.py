import json
import gzip
import logging

logger = logging.getLogger("unicorcli")

# Let's read json files one line at a time so
# the memory footprint doesn't swell when handling
# large files.
#
# The other formats inherently do this.
class JsonFileReader:
    def __init__(self, file_name, delete_after_read=False):
        self.file_handle = open(file_name, mode='rb')
        self.file_name = file_name
        self.saw_end = False
        self.delete_after_read = delete_after_read
        self.end_of_last_good_line = 0

    def __del__(self):
        # We'll close the handle to be nice, as there
        # might be many more to process.
        if ( self.file_handle ):
            self.file_handle.close()

        # Remove the file if and only if we reached the end
        # and need to remove the file.
        # This prevents losing contents if interrupted.
        if ( self.delete_after_read and self.saw_end ):
            os.unlink(self.file_name)
    
    def __iter__(self):
        return self

    # This makes the object iterable so that it can slip in to the
    # existing for ... loops.
    def __next__(self):
        # There might be a corrupted line or two, so let's skip over
        # those because the caller might blow up.
        while True:
            current_offset = self.file_handle.tell()
            line = self.file_handle.readline()
            # Nothing to do if there's no data left, make sure to
            # record if the entire file was read so it might be
            # safely delated later.
            if ( line == b"" ):
                self.saw_end = True
                raise StopIteration
            line = line.decode('utf-8').replace("'", '"')
            try:
                json_obj = json.loads(line)
                # might use this for back-tracking a file that's being written while it's being read. TBD
                self.end_of_last_good_line = self.file_handle.tell()
            except json.JSONDecodeError as e:
                logging.warning(f"JSON decoding error in {format(self.file_name)}:byte {format(current_offset)}: {e}")
                # Handle invalid JSON syntax if needed
                pass
            #logging.debug("Read JSON from file: {}".format(json_objects))
            return json_obj

def read_gzip(file_name):
    f = gzip.open(file_name, 'rb')
    return f

def read_generic(file_name):
    f = open(file_name, mode='rt')
    return f

def read_file(file_path, delete_after_read):
    logging.debug("Parsing {}".format(file_path.absolute()))

    is_minified = False
    file_iter = None
    if file_path.suffix == ".json":
        file_iter = JsonFileReader(file_path.absolute(), delete_after_read=delete_after_read)
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
    if delete_after_read and not file_path.suffix == ".json":
      # We have the data from the file, let's delete the file now
        logging.debug("Deleting {}".format(file_path))
        with open(file_path, 'w') as file:
            file.write("")  # Write an empty string to the file and automatically close it
    #else:
    #    logging.debug("NOT deleting {}".format(file_path))

    return file_iter, is_minified

def write_generic(file_name):
    f = open(file_name, mode='w+')
    return f
