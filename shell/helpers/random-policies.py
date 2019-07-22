#!/usr/bin/python3

import random
import argparse


PERMISSIONS = ['read', 'write', 'create', 'delete', 'audit']

MAX_ATTRIBUTE_COUNT = 5


def convert_to_term(pair):
    [name, user_or_object] = pair.split(',')

    if user_or_object == 'user':
        return '{}(u)'.format(name)

    if user_or_object == 'object':
        return '{}(o)'.format(name)

    return None


def run_main(attribute_list, policy_count, output_filepath=None):
    policies = []

    for i in range(policy_count):
        attribute_count = random.randint(1, min(MAX_ATTRIBUTE_COUNT, len(attribute_list)))
        attribute_pairs = random.sample(attribute_list, attribute_count)

        attribute_terms = [convert_to_term(pair) for pair in attribute_pairs]
        permission = random.choice(PERMISSIONS)

        policies.append('{} :- {}\n'.format(permission, ', '.join(attribute_terms)))

    if output_filepath:
        with open(output_filepath, 'w') as fp:
            fp.writelines(policies)
    else:
        print(''.join(policies))


def __get_parser():
    parser = argparse.ArgumentParser(description="Generates a list of policies")
    parser.add_argument("attrs_fpath", type=str, help="The input attributes list")
    parser.add_argument("policy_count", type=int, help="Number of policies to generate")
    parser.add_argument("-o", dest="output_filepath", type=str, help="Output to file")

    return parser


def command_line_runner():
    parser = __get_parser()
    args = vars(parser.parse_args())

    with open(args['attrs_fpath'], 'r') as attr_fp:
        attribute_list = [input_line.strip() for input_line in attr_fp]

    run_main(attribute_list, args['policy_count'], args.get('output_filepath', None))


if __name__ == "__main__":
    command_line_runner()
