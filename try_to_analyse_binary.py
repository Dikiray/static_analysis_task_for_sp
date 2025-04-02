from elftools.elf.elffile import ELFFile
import argparse
from elftools.elf.dynamic import DynamicSection
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import sys
import subprocess

def check_that_if_file_in_string_it_in_the_end_of_string(file_path):
    result = subprocess.run(["strings", file_path], capture_output=True, text=True).stdout
    result = result.split("\n")
    for s in result:
        if s.find(".c") != -1:
            if not s.endswith(".c"):
                print(s)

def analyze_strings(file_path, print_doc):
    result = subprocess.run(["strings", file_path], capture_output=True, text=True).stdout
    result = result.split("\n")

    print("\n[*]Упомянутые c файлы:")
    for s in result:
        if s.endswith(".c"):
            print(s)
    print("\n[*](скорее всего) c файлы участвовавшие при сборке:")
    for s in result:
        if s.endswith(".c") and s.startswith("../.."):
            print(s)
    if print_doc:
        print("\n[*]Возможный текст документации данного пакета:")
        amt = 10
        result = [""] * amt + result + [""] * amt
        help_syms_amt = [0] * len(result)
        for i in range(0, len(result)):
            s = result[i]
            help_syms_amt[i] += s.count("--")
            help_syms_amt[i] -= s.count("%")
            if result[i].find("--help") != -1:
                help_syms_amt[i] = 10000
            started = 0
            is_first = True
            has_chert = False
            for ch in s:
                if ch != ' ' and ch != '    ':
                    if is_first and ch == '-':
                        has_chert = True
                    is_first = False
                if ch == '<':
                    started = 1
                if ch == '>':
                    if started:
                        help_syms_amt[i] += 1
                        if has_chert:
                            help_syms_amt[i] += 3
                    started = 0


        chosed = [0] * len(result)
        for i in range(amt, len(result) - amt):
            cur_sum = 0
            for j in range(-amt//2, amt//2):
                cur_sum += help_syms_amt[i + j]
            if cur_sum > amt and help_syms_amt[i] >= 0:
                chosed[i + j] = 1

        for i in range(amt, len(result) - amt):
            if chosed[i - amt] + chosed[i] + chosed[i + amt] >= 2:
                chosed[i] = 1

        add_borders = 10
        for i in range(amt, len(result) - amt):
            for j in range(-add_borders, add_borders):
                if chosed[i + add_borders]:
                    chosed[i] = 1

        for i in range(amt, len(result) - amt):
            if chosed[i] and help_syms_amt[i] >= 0:
                print(result[i])

def analyze_binary(file_path, print_doc):
    with open(file_path, 'rb') as f:
        elffile = ELFFile(f)
        print("\n[*] Анализ внешних компонентов:")
        dynamic_section = elffile.get_section_by_name('.dynamic')
        if dynamic_section:
            for tag in dynamic_section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    print(f"  Используется внешняя библиотека: {tag.needed}")

    analyze_strings(file_path, print_doc)

def main():
    parser = argparse.ArgumentParser(
        description="Extracting avaliable information from binaries"
    )
    parser.add_argument("-i", required=True,
                       help="Path to ELF binary file")
    parser.add_argument("-d", required=False,
                        help="Print the potential doc text of file", action=argparse.BooleanOptionalAction)
    args = parser.parse_args()
    analyze_binary(args.i, True if args.d else False)

if __name__ == "__main__":
    main()
