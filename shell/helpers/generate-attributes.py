#!/usr/bin/python3

'''
Creates attribute pairs from a list of words. Automatically skips keywords
@author Judicael Djoko
'''

import argparse

forbidden_words = ['read', 'write', 'create', 'delete', 'audit']


def __get_parser():
    parser = argparse.ArgumentParser(description="Converts wordlist to nexus attribute format")
    parser.add_argument("wordlist_fpath", type=str, help="The input wordlist")
    parser.add_argument("output_fpath", type=str, help="Destination file containing the attributes")
    parser.add_argument("-m", dest="max_attributes", type=int, help="Maximum number of attributes")

    return parser


def command_line_runner():
    parser = __get_parser()
    args = vars(parser.parse_args())

    counter = 0
    skipped = 0

    with open(args['wordlist_fpath'], 'r') as input_fp:
        with open(args['output_fpath'], 'w') as output_fp:
            for input_line in input_fp:
                counter += 1

                input_word = input_line.strip()

                if input_word in forbidden_words:
                    continue

                attribute_type = "user" if counter % 2 else "object"

                output_fp.writelines(["{},{}\n".format(input_word, attribute_type)])

                if counter == args['max_attributes']:
                    break

    print('Completed: {}'.format(counter - skipped))


if __name__ == "__main__":
    command_line_runner()
