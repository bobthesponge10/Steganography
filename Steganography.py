import io
import random
from typing import Optional, Tuple
import math
from PIL import Image
import argparse
import tqdm
from itertools import islice
import hashlib


# From https://stackoverflow.com/questions/1094841/get-human-readable-version-of-file-size
# Bytes to readable format
def sizeof_fmt(num, suffix="b", divisor=1024.0):
    for unit in ("", "K", "M", "G", "T", "P", "E", "Z"):
        if abs(num) < divisor:
            return f"{num:3.1f}{unit}{suffix}"
        num /= divisor
    return f"{num:.1f}Y{suffix}"


class Steganography:
    prefix_len_size = 31  # can't be one less than multiple of 3. EX: 3 is fine but not 2
    # Because end of header cannot be at the end of a pixel due to encoding errors

    default_lsb = 2

    def __init__(self, file_obj_image=None):
        self.image: Optional[Image] = None
        self.pixels = None
        if file_obj_image is not None:
            self.load(file_obj_image)

    def load(self, file_obj_image):
        """
        Loads an input image and converts it to rgb representation.
        :param file_obj_image: either the file path or an io object
        """

        image = Image.open(file_obj_image)
        if image.mode != "RGB":
            image = image.convert("RGB")
        self.image = image
        self.pixels = self.image.load()

    def save(self, filename):
        """
        Saves the image to file
        :param filename:
        """
        self.image.save(filename)

    def size(self) -> Tuple[int, int]:
        """
        Returns the width and height of the image. Returns two zeros if image is not loaded yet
        :return: an int tuple of width and height
        """
        if self.image:
            return self.image.width, self.image.height
        return 0, 0

    def pixel_count(self) -> int:
        """
        Gets the number of pixels in the image. (width * height)
        :return:
        """
        size = self.size()
        return size[0] * size[1]

    @staticmethod
    def stream_bits(bytes_):
        """
        Returns a stream for each bit from a given byte stream
        :param bytes_:
        """
        for b in bytes_:
            for i in range(8):
                yield (b >> i) & 1

    @classmethod
    def stream_bytes(cls, bits):
        """
        Returns a stream of bytes from a given bit stream
        :param bits:
        :return:
        """
        while True:
            d = cls.get_bits(bits, 8, reverse=True)
            if d is None:
                return
            yield d

    @staticmethod
    def get_bits(bit_stream, bits, reverse=False):
        """
        Returns x number of bits from a given bit stream as an unsigned int.
        :param bit_stream:
        :param bits: Number of bits to grab
        :param reverse: Reverses the order the bits are added to the output int
        :return:
        """
        output = 0
        for i in range(bits):
            if reverse:
                output = output >> 1
            else:
                output = output << 1
            try:
                v = bit_stream.__next__()
                if reverse:
                    output = output | (v << (bits-1))
                else:
                    output = output | v
            except StopIteration:
                if i == 0:
                    return None
        return output

    @staticmethod
    def read_from_generator(generator, number):
        """
        Returns a list of 'number' items from a stream, returns less than requested if stream ends
        :param generator:
        :param number: the number of items to take from the stream
        :return:
        """
        output = []
        for _ in range(number):
            try:
                output.append(next(generator))
            except StopIteration:
                return output
        return output

    def read_pixel_gen(self, read_positions=None):
        """
        Creates a stream of pixels from the current image, by default goes left to right, top to bottom but can
        be given a 1d array of positions to use as an order instead
        :param read_positions: a 1d list of positions with values ranging from 0 - (self.pixel_count()-1) inclusive
        """

        size = self.size()
        if read_positions is None:
            for y in range(self.image.height):
                for x in range(self.image.width):
                    yield self.pixels[x, y]
        else:
            for pos in read_positions:
                x = pos % size[0]
                y = int(pos//size[0])
                yield self.pixels[x, y]

    def write_pixel_gen(self, pixel_stream, write_positions=None):
        """
        Writes pixels to the image from a given stream, by default writes left to right, top to bottom but can
        be give a 1d array of positions to use as an order instead
        :param pixel_stream: an iterable of pixels
        :param write_positions: a 1d list of positions with values ranging from 0 - (self.pixel_count()-1) inclusive
        """

        if write_positions is not None:
            write_positions = iter(write_positions)
        size = self.size()

        for index, pixel in enumerate(pixel_stream):
            if write_positions is not None:
                index = next(write_positions)
            x = index % size[0]
            y = int(index // size[0])
            self.pixels[x, y] = pixel

    def write_prefix(self, message_size, lsb):
        """
        Takes header params and writes them to bytes
        :param message_size: the size of data writen to the image
        :param lsb: the lsb encoding to use
        :return:
        """
        size = message_size

        output = size.to_bytes(self.prefix_len_size, byteorder="big", signed=False)
        output += lsb.to_bytes(1, byteorder="big", signed=False)
        return output

    def read_prefix(self, stream):
        """
        Reads the prefix from a byte stream and returns a dictionary of values
        :param stream:
        :return:
        """
        message_size = int.from_bytes(self.read_from_generator(stream, self.prefix_len_size), byteorder="big",
                                      signed=False)
        lsb = int.from_bytes(self.read_from_generator(stream, 1), byteorder="big", signed=False)

        if lsb > 8:
            raise Exception(f"Failed to parse header: got lsb of {lsb} which is larger than 8")

        return {"size": message_size, "lsb": lsb}

    @staticmethod
    def message_stream(prefix, message_bytes, lsb, encoding_state, fill):
        """
        Streams a given prefix and message and switches the encoding between them
        :param prefix: the bytes for the prefix
        :param message_bytes: an iterable of the message bytes
        :param lsb: the lsb bits to use for encoding the message
        :param encoding_state: the dictionary object used to control the encoding settings in real time
        :param fill: controls if at the end of the normal stream, to just endlessly return random bytes
        """
        for index, i in enumerate(prefix):
            yield i

        encoding_state["lsb"] = lsb

        for index, i in enumerate(message_bytes):
            yield i

        if not fill:
            return

        while True:
            r = random.randint(0, 255)
            yield r

    def generate_message_stream(self, message_bytes, lsb, encoding_state, fill):
        """
        Creates a prefix for a given message and lsb and creates the stream of both
        :param message_bytes: an iterable of the message bytes
        :param lsb: the lsb buts to use for the encoding of the message
        :param encoding_state: the dictionary object used to control the encoding settings in real time
        :param fill: controls if at the end of the normal stream, to just endlessly return random bytes
        :return:
        """

        message_size = len(message_bytes)
        prefix = self.write_prefix(message_size, lsb)

        encoding_state["lsb"] = self.default_lsb
        encoding_state["size"] = message_size + 1 + self.prefix_len_size
        encoding_state["fill"] = fill
        return self.message_stream(prefix, message_bytes, lsb, encoding_state, fill)

    def write_data(self, message_bytes, min_lsb=1, max_lsb=0, password=None, fill=False, iterator_=None):
        """
        Encodes and writes the message to the current image
        :param message_bytes: an iterable of message bytes
        :param min_lsb: the lowest allowed value for the lsb to be, can be any value from 1-8 but cannot be higher than
        the max_lsb
        :param max_lsb: the highest allowed value for the lsb to be, can be any value from 1-8 but cannot be lower than
        the min_lsb
        :param password: optional password used to shuffle the order of pixels writen to
        :param fill: boolean controlling whether to fill the leftover space with random bits
        :param iterator_: an optional iterator used to wrap the encoding stream intended to monitor progress
        :return:
        """
        if max_lsb == 0:
            max_lsb = 4
        if self.image is None:
            return

        prefix_len = self.prefix_len_size + 1
        prefix_pixels = math.ceil((prefix_len * 8) / (3 * self.default_lsb))

        size = self.image.width, self.image.height
        usable_pixels = size[0] * size[1] - prefix_pixels

        message_len = len(message_bytes)
        message_bits = message_len * 8

        bits_per_lsb = usable_pixels * 3

        max_bits = bits_per_lsb * max_lsb
        max_bytes = int(max_bits//8)

        lsb = math.ceil(message_bits / bits_per_lsb)
        lsb = max(min_lsb, lsb)

        if message_len > max_bytes or lsb > max_bits:
            raise Exception(f"Not enough space to write data, max size of {sizeof_fmt(max_bytes)} bytes"
                            f" allowed. Tried to write {sizeof_fmt(message_len)} bytes")

        encoding_state = {}
        message = self.generate_message_stream(message_bytes, lsb, encoding_state, fill)

        inverse_shuffle = None

        if password:
            password = int(hashlib.sha1(password.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
            shuffle_order = list(range(self.pixel_count()))
            inverse_shuffle = shuffle_order.copy()

            R = random.Random(password)
            R.shuffle(shuffle_order)

            for index, i in enumerate(shuffle_order):
                inverse_shuffle[index] = i

            pixel_input = self.read_pixel_gen(shuffle_order)
        else:
            pixel_input = self.read_pixel_gen()

        if iterator_:
            encoded_pixels = self.set_pixel_stream(iterator_(pixel_input, encoding_state), message, encoding_state)
        else:
            encoded_pixels = self.set_pixel_stream(pixel_input, message, encoding_state)

        if inverse_shuffle is not None:
            self.write_pixel_gen(encoded_pixels, inverse_shuffle)
        else:
            self.write_pixel_gen(encoded_pixels)

    def read_data(self, password=None, iterator_=None):
        """
        Reads encoded data from the current image
        :param password: optional password used to shuffle the order of pixels read from
        :param iterator_: an optional iterator used to wrap the decoding stream intended to monitor progress
        :return:
        """
        header_data = {"lsb": 2, "size": 0}

        if password:
            password = int(hashlib.sha1(password.encode("utf-8")).hexdigest(), 16) % (10 ** 8)
            shuffle_order = list(range(self.pixel_count()))
            R = random.Random(hash(password))
            R.shuffle(shuffle_order)
            pixel_input = self.read_pixel_gen(shuffle_order)
        else:
            pixel_input = self.read_pixel_gen()

        if iterator_ is not None:
            pixel_input = iterator_(pixel_input, header_data)

        read_bit_stream = self.read_pixel_stream_to_bit_stream(pixel_input, header_data)
        read_byte_stream = self.stream_bytes(read_bit_stream)

        header_data.update(self.read_prefix(read_byte_stream))

        read_byte_stream = islice(read_byte_stream, 0, header_data["size"])

        ds = io.BytesIO(bytes(read_byte_stream))

        return ds

    @classmethod
    def set_pixel_stream(cls, input_pixels, data_stream, encoding_state):
        """
        Given a pixel stream and data stream, outputs a modified pixel stream with the data encoded according to the
        encoding_state value which may change as encoding is happening
        :param input_pixels:
        :param data_stream:
        :param encoding_state:
        """
        bit_stream = cls.stream_bits(data_stream)
        for pixel in input_pixels:
            try:
                yield cls.set_pixel(pixel, bit_stream, encoding_state)
            except StopIteration:
                break

    @classmethod
    def set_pixel(cls, pixel, bit_stream, encoding_state):
        """
        Given an input pixel value and bit stream, outputs a modified pixel with the data encoded according to the
        encoding_state value
        :param pixel:
        :param bit_stream:
        :param encoding_state:
        :return:
        """
        lsb = encoding_state.get("lsb", cls.default_lsb)

        mask = int(2 ** (8 - lsb) - 1) << lsb
        parts = [pixel[0], pixel[1], pixel[2]]
        output = pixel

        for i, p in enumerate(parts):
            bits = cls.get_bits(bit_stream, lsb, reverse=True)
            if bits is not None:
                parts[i] = (p & mask) | bits
                # parts[i] = bits << (8-lsb)
                output = tuple(parts)
            elif i == 0:
                raise StopIteration
        return output

    @classmethod
    def read_pixel_as_bit_stream(cls, pixel, header):
        """
        Returns a bit stream of data from a given pixel value according to the decoding information in the header value
        :param pixel:
        :param header:
        """
        lsb = header.get("lsb", cls.default_lsb)

        parts = [pixel[0], pixel[1], pixel[2]]
        for i, p in enumerate(parts):
            for j in range(lsb):
                yield (p >> j) & 1

    @classmethod
    def read_pixel_stream_to_bit_stream(cls, pixels, header):
        """
        Returns a stream of bits from a stream of pixel values according to the header value which may change while
        running
        :param pixels:
        :param header:
        """
        for pixel in pixels:
            bits = cls.read_pixel_as_bit_stream(pixel, header)
            for i in bits:
                yield i


parser = argparse.ArgumentParser(prog="Steganography Encoder/Decoder",
                                 description="Encode a file into an image or Extract a file from an image.",
                                 epilog="Saving to a non-lossless image format (like jpg) will most likely corrupt"
                                        " the encoded data")

parser.add_argument("image", type=argparse.FileType("rb"),
                    help="The input image file to either add data to or extract data from")
parser.add_argument("-i", "--input", required=False, type=argparse.FileType("rb"),
                    help="The file whose data you want to embed inside the image")
parser.add_argument("output", type=argparse.FileType("wb"),
                    help="The file to save either the image or extracted data to depending on if a "
                         "file is given in the --input argument")
parser.add_argument("-q", "--quiet", action="store_true", help="Hides all progress bars, messages, and errors")
parser.add_argument("--min", default=1, type=int, help="The minimum number of bits to use for the lsb "
                                                       "encoding any integer from 1-8")
parser.add_argument("--max", default=4, type=int, help="The maximum number of bits to use for the lsb"
                                                       " encoding any integer from 1-8")
parser.add_argument("-p", "--password", type=str, required=False, help="Optional password used to encode "
                                                                       "or decode data from an image")
parser.add_argument("-f", "--fill", action="store_true", help="Fills leftover space with random bits")


args = parser.parse_args()


def log(*args_, **kwargs):
    if not args.quiet:
        print(*args_, **kwargs)


def error(*args_, **kwargs):
    if not args.quiet:
        parser.error(*args_, **kwargs)
    exit(1)


if args.min < 1 or args.min > 8:
    error("Minimum lsb encoding set outside the range of 1-8 inclusive")
if args.max < 1 or args.max > 8:
    error("Maximum lsb encoding set outside the range of 1-8 inclusive")
if args.min > args.max:
    error("Minimum number of bits set higher than the maximum number of bits for the lsb")


log("Loading image")
s = Steganography(args.image)
log("Loaded image")

if args.input is None:
    bar = None
    iterator = None
    output_data = None
    log("Decoding")

    if not args.quiet:
        bar = tqdm.tqdm(desc="Initializing decoding", unit="b", unit_scale=True, unit_divisor=1024)

        def it(input_, encoding_state):
            total = None
            bar.desc = "Decoding pixels"
            bar.refresh()
            for i in input_:
                if total is None:
                    if encoding_state["size"] > 0:
                        total = encoding_state["size"]
                        bar.total = total * 8
                        bar.refresh()
                bar.update(encoding_state["lsb"] * 3)
                yield i
        iterator = it

    try:
        output_data = s.read_data(password=args.password, iterator_=iterator)
        if bar is not None:
            bar.close()
    except Exception as e:
        if bar is not None:
            bar.desc = "Error"
            bar.refresh()
            bar.close()
        error(f"Failed to extract data from image: {e}")

    log("Decoding finished")
    log(f"Saving decoded file to: {args.output.name}")
    args.output.write(output_data.read())
    log(f"Saved decoded data to: {args.output.name}")

else:
    bar = None
    iterator = None
    input_data = args.input.read()
    log("Encoding")

    if not args.quiet:
        bar = tqdm.tqdm(desc="Initializing encoding", unit="b", unit_scale=True, unit_divisor=1024)

        def it(input_, encoding_state):
            lsb = encoding_state['lsb']
            bar.total = encoding_state["size"] * 8
            bar.desc = f"[lsb:{lsb}] Encoding pixels"
            bar.refresh()

            change = False
            for i in input_:
                bar.update(encoding_state["lsb"] * 3)
                if not change and bar.n >= bar.total and encoding_state["fill"]:
                    lsb = encoding_state["lsb"]
                    bar.desc = f"[lsb:{lsb}] Filling space"
                    change = True
                    bar.refresh()
                elif lsb != encoding_state["lsb"]:
                    lsb = encoding_state["lsb"]
                    bar.desc = f"[lsb:{lsb}] Encoding pixels"
                    bar.refresh()

                yield i
        iterator = it

    try:
        s.write_data(input_data, max_lsb=args.max, min_lsb=args.min, password=args.password,
                     fill=args.fill, iterator_=iterator)
        if bar is not None:
            bar.close()
    except Exception as e:
        if bar is not None:
            bar.desc = "Error"
            bar.refresh()
            bar.close()
        error(f"Failed to encode data to image: {e}")

    log("Encoded")
    log(f"Saving to: {args.output.name}")
    s.save(args.output)
    log(f"Saved to: {args.output.name}")
