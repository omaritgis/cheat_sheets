from PyPDF2 import PdfFileReader, PdfFileWriter
import sys

def decrypt_pdf(input_path, output_path, password):
    with open(input_path, 'rb') as input_file, \
        open(output_path, 'wb') as output_file:
        reader = PdfFileReader(input_file)
        reader.decrypt(password)
        writer = PdfFileWriter()
        for page in range(reader.getNumPages()):
            writer.addPage(reader.getPage(page))
        writer.write(output_file)

def gen_wlist():
    chars_list = ['x', 'y', 'z', 'Z', '1']
    for i in chars_list:
        for j in chars_list:
            for k in chars_list:
                for l in chars_list:
                    for m in chars_list:
                        word = i+j+k+l+m 
                        try:
                            decrypt_pdf('test.pdf', 'test.pdf', word)
                            sys.exit(0)
                        except:
                            pass